//! SD3, SD4: test-only setup and pass runner. SD4: removed in Stage 2/3.

use crate::{
    import::{self, ImportOutcome},
    store::{self, AnnotationRow, Store},
    sync::{
        clock::Hlc,
        crypto::{self, Keypair},
        device_store::{DeviceStore, LibraryState, Memory},
        enrollment,
        envelope::Signer,
        files,
        folder::{Disk, Folder},
        ids::{b64url_encode, Id16},
        journal, membership, pass, trust,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const BOOK: &str = "standardebooks-moby-dick.epub";
const STORAGE: &str = "b5-test-folder";

#[derive(Default)]
pub struct SyncSlice(Mutex<Option<Slice>>);

struct Slice {
    endpoints: [Endpoint; 2],
    shared: PathBuf,
    _root: tempfile::TempDir,
    started: Instant,
}

struct Endpoint {
    root: PathBuf,
    lib: journal::Library,
    keys: Memory,
    book: String,
    hash: String,
}

impl Endpoint {
    fn new(
        root: PathBuf,
        source: &Path,
        id: Id16,
        identity: LibraryState,
        book_match: &str,
        confirmed: crate::sync::ids::Hash32,
    ) -> Result<Self> {
        let library = import::Library::new(&root)?;
        let mut store = Store::open(&root.join("linen.db"))?;
        let ImportOutcome::Imported { book_id: book, .. } =
            import::import_book(&mut store, &library, source)?
        else {
            return Err("test EPUB could not be imported".into());
        };
        let hash = store.conn().query_row(
            "SELECT content_hash FROM books WHERE id = ?1",
            [&book],
            |r| r.get(0),
        )?;
        let lib = journal::Library {
            id,
            device: identity.device_id()?,
        };
        journal::join(store.conn(), &lib, STORAGE, store::now_ms())?;
        // SD4: books themselves are outside this slice. The same fixture EPUB is
        // imported separately and matched before any place or annotation is saved.
        store.conn().execute(
            "INSERT INTO sync_books (library, sync_id, book_id) VALUES (?1, ?2, ?3)",
            rusqlite::params![id.to_string(), book_match, book],
        )?;
        let mut state = pass::State::default();
        state.membership.confirmed.insert(confirmed);
        state.save(store.conn(), &id)?;
        let keys = Memory::default();
        let mut device = DeviceStore::default();
        device.libraries.insert(id.to_string(), identity);
        device.save(&keys)?;
        Ok(Self {
            root,
            lib,
            keys,
            book,
            hash,
        })
    }

    fn store(&self) -> Result<Store> {
        Ok(Store::open(&self.root.join("linen.db"))?)
    }

    fn pass(&self, shared: &Path, started: Instant) -> Result<()> {
        let mut folder = Disk::open(shared)?;
        let mut keys = DeviceStore::load(&self.keys)?;
        let db = Mutex::new(self.store()?);
        let state = pass::State::load(
            db.lock().map_err(|_| "test store lock poisoned")?.conn(),
            &self.lib.id,
        )?;
        let mut device = pass::Device {
            db: pass::Database::Store(&db),
            root: &self.root,
            lib: self.lib,
            store: &mut keys,
            ks: &self.keys,
            state,
            name: "B5 test device",
        };
        let mono = || started.elapsed().as_millis() as u64;
        let report = pass::run(
            &mut device,
            &mut folder,
            pass::Readings {
                mono_ms: mono(),
                wall_ms: store::now_ms() as u64,
                clock_ahead: false,
                same_boot: true,
            },
            &pass::Budgets::sy2(),
            &mono,
        )?;
        if report.stopped.is_some() || report.paused || report.asking.is_some() {
            return Err(format!("test pass stopped: {report:?}").into());
        }
        Ok(())
    }
}

/// Write and read via PS3, so enrollment uses the same bytes the partner sees.
fn exchange(folder: &mut Disk, path: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    files::write_file(folder, path, bytes)?;
    let dir = path
        .rsplit_once('/')
        .ok_or("expected an enrollment path")?
        .0;
    let file = folder
        .list(dir, None)?
        .entries
        .into_iter()
        .find(|file| file.name == path)
        .ok_or("enrollment file missing")?;
    match files::read_file(folder, &file)? {
        files::Read::Bytes(bytes) => Ok(bytes),
        _ => Err("enrollment file unavailable".into()),
    }
}

impl Slice {
    fn setup(source: &Path) -> Result<Self> {
        let root = tempfile::Builder::new().prefix("linen-b5-").tempdir()?;
        let shared = root.path().join("shared");
        fs::create_dir(&shared)?;
        let mut folder = Disk::open(&shared)?;
        let id = Id16(crypto::random()?);
        let naming: [u8; 32] = crypto::random()?;
        let mut first = LibraryState::new()?;
        let mut second = LibraryState::new()?;
        let key = first.key()?;
        let writer = first.writer_id()?;
        let second_writer = second.writer_id()?;
        let time = store::now_ms();
        let code_key = Keypair::generate()?;
        let nonce: [u8; 16] = crypto::random()?;
        let (genesis_bytes, genesis) = trust::sign(
            "genesis",
            &id,
            json!({"device": key.device().to_string(), "key": b64url_encode(&key.public()),
                "label": "B5 first", "clock": [time, 0],
                "code": {"nonce": b64url_encode(&nonce), "codeKey": b64url_encode(&code_key.public())}}),
            &[
                (&key, Signer::Device(key.device()), 0),
                (&code_key, Signer::Code, 0),
            ],
        );
        let genesis_bytes = exchange(&mut folder, &trust::trust_path(&genesis), &genesis_bytes)?;
        let (claim, _) = trust::sign(
            "claim",
            &id,
            json!({
                "device": key.device().to_string(), "writer": writer.to_string(),
                "key": b64url_encode(&key.public()), "genesis": genesis.to_string(),
            }),
            &[(&key, Signer::Device(key.device()), 0)],
        );
        files::write_file(&mut folder, &trust::claim_path(&id), &claim)?;

        let (applicant, request) = enrollment::request(&id, &second_writer, "B5 second")?;
        let me = applicant.request.applicant;
        let request = exchange(&mut folder, &enrollment::request_path(&me), &request)?;
        let request = enrollment::open_request(&request, &id)?;
        let (answering, answer) = enrollment::answer(&id, &request, &key, &writer)?;
        let answer = exchange(
            &mut folder,
            &enrollment::answer_path(&me, &key.device()),
            &answer,
        )?;
        let answer = enrollment::open_answer(&answer, &id, &key.public())?;
        let reveal = enrollment::reveal(&id, &applicant, &answer, &second_writer)?;
        let reveal = exchange(&mut folder, &enrollment::reveal_path(&me), &reveal)?;
        let reveal = enrollment::open_reveal(&reveal, &id, &answering)?;
        let (transcript, code) = enrollment::code_enrolled(&id, &answering, &reveal, &key.public());
        if enrollment::code_applicant(&id, &applicant, &answer, &key.public()) != (transcript, code)
        {
            return Err("enrollment codes differ".into());
        }
        // SD4: the test confirms the displayed code without setup screens.
        let (enroll_bytes, enrolled) = enrollment::enroll(
            &id,
            &genesis,
            &answering,
            &reveal,
            &transcript,
            &key,
            1,
            Hlc(time as u64, 1),
        );
        let enroll_bytes = exchange(&mut folder, &trust::trust_path(&enrolled), &enroll_bytes)?;
        let records = BTreeMap::from([
            (genesis, trust::open(&genesis_bytes, &id, &genesis)?),
            (enrolled, trust::open(&enroll_bytes, &id, &enrolled)?),
        ]);
        let confirmed = BTreeSet::from([enrolled]);
        let members = membership::compute(&membership::Inputs {
            genesis,
            records: &records,
            first_seen: &BTreeMap::new(),
            confirmed: &confirmed,
            checkpoint: &BTreeSet::new(),
            held: &|_, _| None,
            accepted: &BTreeSet::new(),
            now_ms: time,
            me: Some(me),
            quarantined: &BTreeMap::new(),
            heads: &BTreeMap::new(),
        })
        .map_err(|reason| format!("test enrollment membership: {reason:?}"))?;
        let checkpoint = enrollment::Checkpoint {
            head: enrolled,
            removals: vec![],
            own: None,
            view: None,
            counter: 1,
            floors: vec![],
            frontier: vec![],
            marks: vec![],
        };
        let ok = enrollment::enroll_ok(
            &id,
            &answering,
            &transcript,
            &enrolled,
            &checkpoint,
            &naming,
            &key,
            &writer,
        )?;
        let ok = exchange(&mut folder, &enrollment::ok_path(&me, &key.device()), &ok)?;
        let joined = enrollment::join(
            &ok,
            &id,
            &applicant,
            &answer,
            &key.public(),
            &members,
            &records,
        )?;
        second.seed = b64url_encode(&applicant.key.seed());
        second.device = me.to_string();
        second.floors = joined.floors();
        for (state, naming_key) in [(&mut first, naming), (&mut second, joined.naming_key)] {
            state
                .rest
                .insert("genesis".into(), json!(genesis.to_string()));
            state
                .rest
                .insert("head".into(), json!(enrolled.to_string()));
            state
                .rest
                .insert("namingKey".into(), json!(b64url_encode(&naming_key)));
        }
        let book_match = uuid::Uuid::new_v4().to_string();
        let endpoints = [
            Endpoint::new(
                root.path().join("a"),
                source,
                id,
                first,
                &book_match,
                enrolled,
            )?,
            Endpoint::new(
                root.path().join("b"),
                source,
                id,
                second,
                &book_match,
                enrolled,
            )?,
        ];
        Ok(Self {
            endpoints,
            shared,
            _root: root,
            started: Instant::now(),
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Action {
    Setup,
    Pass {
        side: usize,
    },
    Save {
        cfi: String,
        fraction: f64,
        range: String,
        quote: String,
    },
    Edit {
        note: String,
    },
    Read {
        side: usize,
    },
    Reset,
}

fn apply(
    session: &mut Option<Slice>,
    action: Action,
    setup: impl FnOnce() -> Result<Slice>,
) -> Result<Value> {
    let endpoint = |slice: &Slice, side: usize| -> Result<()> {
        if side >= slice.endpoints.len() {
            return Err("invalid test library".into());
        }
        Ok(())
    };
    match action {
        Action::Setup => {
            *session = Some(setup()?);
            return Ok(json!({"configured": true}));
        }
        Action::Reset => {
            *session = None;
            return Ok(json!({"configured": false}));
        }
        _ => {}
    }
    // SD3: no fixture paths, store, or shared folder are opened before setup.
    let Some(slice) = session else {
        return Ok(json!({"configured": false}));
    };
    match action {
        Action::Pass { side } => {
            endpoint(slice, side)?;
            slice.endpoints[side].pass(&slice.shared, slice.started)?;
            Ok(json!({"configured": true}))
        }
        Action::Save {
            cfi,
            fraction,
            range,
            quote,
        } => {
            let a = &slice.endpoints[0];
            let mut store = a.store()?;
            store.save_position(&a.book, &cfi, fraction, None)?;
            let now = store::now_ms();
            store.save_annotation(&AnnotationRow {
                id: uuid::Uuid::new_v4().to_string(),
                book_id: a.book.clone(),
                anchored_content_hash: a.hash.clone(),
                color: "yellow".into(),
                cfi_range: range,
                quote_exact: quote,
                quote_prefix: String::new(),
                quote_suffix: String::new(),
                note: Some("made in A".into()),
                created_at: now,
                updated_at: now,
                anchor_status: "anchored".into(),
            })?;
            Ok(json!({"configured": true}))
        }
        Action::Edit { note } => {
            let b = &slice.endpoints[1];
            let mut store = b.store()?;
            let mut annotation = store
                .annotations(&b.book)?
                .pop()
                .ok_or("synced highlight missing")?;
            annotation.note = Some(note);
            annotation.updated_at = store::now_ms();
            store.save_annotation(&annotation)?;
            Ok(json!({"configured": true}))
        }
        Action::Read { side } => {
            endpoint(slice, side)?;
            let device = &slice.endpoints[side];
            let store = device.store()?;
            Ok(
                json!({"configured": true, "position": store.position(&device.book)?,
                "annotations": store.annotations(&device.book)?}),
            )
        }
        Action::Setup | Action::Reset => unreachable!(),
    }
}

#[tauri::command]
pub fn spike_sync_slice(
    state: tauri::State<'_, SyncSlice>,
    action: Action,
) -> std::result::Result<Value, String> {
    let mut session = state.0.lock().map_err(|_| "test sync lock poisoned")?;
    apply(&mut session, action, || {
        Slice::setup(&super::repo_root().join("corpus/cache").join(BOOK))
    })
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_setup_does_not_initialize_or_open_a_library_or_disk() {
        let mut session = None;
        assert_eq!(
            apply(&mut session, Action::Pass { side: 0 }, || panic!(
                "opened test roots"
            ))
            .unwrap(),
            json!({"configured": false})
        );
        assert!(session.is_none());
    }

    #[test]
    fn the_two_disk_libraries_exchange_place_and_note() {
        let mut session =
            Some(Slice::setup(&super::super::repo_root().join("corpus/cache").join(BOOK)).unwrap());
        let mut run = |action| apply(&mut session, action, || unreachable!()).unwrap();
        let cfi = "epubcfi(/6/4!/4/2/1:0)";
        run(Action::Save {
            cfi: cfi.into(),
            fraction: 0.25,
            range: "epubcfi(/6/4!/4/2,/1:0,/1:4)".into(),
            quote: "Call".into(),
        });
        run(Action::Pass { side: 0 });
        run(Action::Pass { side: 1 });
        let received = run(Action::Read { side: 1 });
        assert_eq!(received["position"], json!([cfi, 0.25]));
        assert_eq!(received["annotations"][0]["note"], "made in A");
        run(Action::Edit {
            note: "edited in B".into(),
        });
        run(Action::Pass { side: 1 });
        run(Action::Pass { side: 0 });
        assert_eq!(
            run(Action::Read { side: 0 })["annotations"][0]["note"],
            "edited in B"
        );
    }
}
