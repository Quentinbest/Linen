//! PS5: caller-owned state saved alongside each completed step.
use super::ids::{DeviceId, Hash32, Id16};
use super::trust::Mark;
use super::{ages, freshness, hold, retention, weeks};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// PS6: per-pass limits. The SY2 values are PROVISIONAL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    pub names: u64,
    pub devices: u64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    /// SP15: the most change-file bytes one peer's run holds in memory at once,
    /// past the lowest floor checkpoint the run has to reach (the peer cache's
    /// 32 MB per peer, PROVISIONAL).
    pub run_bytes: u64,
    /// SP26's cap on what is listed of a removed device's changes after its cutoff:
    /// files and bytes of them. A value over SP26's (500, 64 MB) is cut to it.
    pub tail_files: u64,
    pub tail_bytes: u64,
}

impl Budgets {
    pub fn sy2() -> Self {
        Self {
            names: 100_000,
            devices: 32,
            bytes: 256 * 1024 * 1024,
            elapsed_ms: 60_000,
            run_bytes: 32 << 20,
            tail_files: super::late::MAX_LATE as u64,
            tail_bytes: super::late::MAX_LATE_BYTES,
        }
    }
}

// PS5: JSON object keys cannot represent structured identifiers.
macro_rules! map_module {
    ($name:ident, $map:ident, $bound:path) => {
        pub(crate) mod $name {
            use serde::{Deserialize, Deserializer, Serialize, Serializer};
            use std::collections::$map;
            pub fn serialize<S: Serializer, K: Serialize + $bound, V: Serialize>(
                map: &$map<K, V>,
                s: S,
            ) -> Result<S::Ok, S::Error> {
                map.iter().collect::<Vec<_>>().serialize(s)
            }
            pub fn deserialize<
                'de,
                D: Deserializer<'de>,
                K: Deserialize<'de> + $bound,
                V: Deserialize<'de>,
            >(
                d: D,
            ) -> Result<$map<K, V>, D::Error> {
                Ok(Vec::<(K, V)>::deserialize(d)?.into_iter().collect())
            }
        }
    };
}
map_module!(map, BTreeMap, Ord);
// HashMap also needs Eq, supplied by the Hash bound's companion trait below.
pub(crate) mod hash_map {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::{collections::HashMap, hash::Hash};
    pub fn serialize<S: Serializer, K: Serialize + Eq + Hash, V: Serialize>(
        map: &HashMap<K, V>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        map.iter().collect::<Vec<_>>().serialize(s)
    }
    pub fn deserialize<
        'de,
        D: Deserializer<'de>,
        K: Deserialize<'de> + Eq + Hash,
        V: Deserialize<'de>,
    >(
        d: D,
    ) -> Result<HashMap<K, V>, D::Error> {
        Ok(Vec::<(K, V)>::deserialize(d)?.into_iter().collect())
    }
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MembershipState {
    #[serde(with = "map")]
    pub first_seen: BTreeMap<Hash32, i64>,
    pub confirmed: BTreeSet<Hash32>,
    pub checkpoint: BTreeSet<Hash32>,
    #[serde(with = "map")]
    pub quarantined: BTreeMap<DeviceId, Option<Mark>>,
    #[serde(with = "map")]
    pub heads: BTreeMap<DeviceId, Option<Hash32>>,
}
/// SP16: a peer's change with its own signature, which a `frontier` entry carries
/// so that it proves itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMark {
    pub s: u64,
    pub h: Hash32,
    /// The signature, base64url.
    pub sig: String,
}
/// What this device holds of a peer's signature: `candidate` is saved before the
/// peer's changes are applied, `confirmed` once this device has applied that change.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerSig {
    pub confirmed: Option<SignedMark>,
    pub candidate: Option<SignedMark>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Sigs {
    #[serde(with = "map")]
    pub peers: BTreeMap<DeviceId, PeerSig>,
}
#[derive(Debug)]
pub struct State {
    pub ledger: hold::Ledger,
    pub weeks: weeks::KnownWeeks,
    pub heard: freshness::Heard,
    pub marks: ages::Marks,
    pub ages: retention::Ages,
    pub vouched: retention::Vouched,
    pub membership: MembershipState,
    /// SP16: the signatures a frontier needs (PS5).
    pub sigs: Sigs,
    /// SP18: what this device knows of the view each peer's device file names.
    pub views: super::views::Notes,
    /// SY23, SP16: the blobs found damaged, the repairs made, and the peers' reports
    /// of damage waiting to be looked at.
    pub objects: super::repair::Objects,
    /// PS5, SY17: whether `vouched` was loaded from a saved row. A clock that
    /// was never saved starts at the current readings in `resume`, rather than
    /// counting everything since the Unix epoch as elapsed.
    started: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            ledger: Default::default(),
            weeks: Default::default(),
            heard: Default::default(),
            marks: Default::default(),
            ages: Default::default(),
            vouched: retention::Vouched::new(0),
            membership: Default::default(),
            sigs: Default::default(),
            views: Default::default(),
            objects: Default::default(),
            started: false,
        }
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the library store lock was poisoned")]
    StoreLock,
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Folder(#[from] std::io::Error),
    #[error(transparent)]
    Store(#[from] super::device_store::StoreError),
    /// SP37 (1): the device store doesn't hold a usable identity for this library.
    #[error("the device store has no usable identity for this library")]
    NoIdentity,
    /// SP20, SP21: membership can't be computed from what storage holds.
    #[error("membership can't be computed: {0:?}")]
    Membership(super::membership::NoMembership),
    #[error(transparent)]
    Journal(#[from] super::journal::JournalError),
    #[error(transparent)]
    Device(#[from] super::device_file::DeviceError),
    #[error(transparent)]
    Chain(#[from] super::chain::ChainError),
    #[error(transparent)]
    Hold(#[from] hold::HoldError),
    #[error(transparent)]
    Backup(#[from] super::backup::BackupError),
    #[error(transparent)]
    Late(#[from] super::late::LateError),
}
fn read<T: DeserializeOwned + Default>(
    conn: &Connection,
    lib: &Id16,
    name: &str,
) -> Result<T, Error> {
    let json: Option<String> = conn
        .query_row(
            "SELECT json FROM sync_pass_state WHERE library = ?1 AND name = ?2",
            params![lib.to_string(), name],
            |r| r.get(0),
        )
        .optional()?;
    json.map(|s| serde_json::from_str(&s).map_err(Error::from))
        .unwrap_or_else(|| Ok(T::default()))
}
fn write<T: Serialize>(tx: &Connection, lib: &Id16, name: &str, value: &T) -> Result<(), Error> {
    tx.execute("INSERT INTO sync_pass_state (library, name, json) VALUES (?1, ?2, ?3) ON CONFLICT(library, name) DO UPDATE SET json = excluded.json", params![lib.to_string(), name, serde_json::to_string(value)?])?;
    Ok(())
}
impl State {
    pub fn load(conn: &Connection, lib: &Id16) -> Result<Self, Error> {
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM sync_pass_state WHERE library = ?1 AND name = 'vouched'",
                [lib.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(Self {
            ledger: read(conn, lib, "ledger")?,
            weeks: read(conn, lib, "weeks")?,
            heard: read(conn, lib, "heard")?,
            marks: read(conn, lib, "marks")?,
            ages: read(conn, lib, "ages")?,
            started: json.is_some(),
            vouched: json
                .map(|s| serde_json::from_str(&s))
                .transpose()?
                .unwrap_or_else(|| retention::Vouched::new(0)),
            membership: read(conn, lib, "membership")?,
            sigs: read(conn, lib, "sigs")?,
            views: read(conn, lib, "views")?,
            objects: read(conn, lib, "objects")?,
        })
    }
    pub fn save(&self, tx: &Connection, lib: &Id16) -> Result<(), Error> {
        write(tx, lib, "ledger", &self.ledger)?;
        write(tx, lib, "weeks", &self.weeks)?;
        write(tx, lib, "heard", &self.heard)?;
        write(tx, lib, "marks", &self.marks)?;
        write(tx, lib, "ages", &self.ages)?;
        write(tx, lib, "vouched", &self.vouched)?;
        write(tx, lib, "membership", &self.membership)?;
        write(tx, lib, "sigs", &self.sigs)?;
        write(tx, lib, "views", &self.views)?;
        write(tx, lib, "objects", &self.objects)
    }
    /// SY17: resume the same vouched clock used by ages and hearing history.
    pub fn resume(&mut self, mono_ms: u64, wall_ms: u64, clock_ahead: bool, same_boot: bool) {
        if !self.started {
            // PS5, SY17: a library's first pass starts the clock now; a restart
            // from the default would add the time since the Unix epoch.
            self.vouched = retention::Vouched::new(wall_ms);
            self.started = true;
        }
        self.vouched
            .restart(mono_ms, wall_ms, clock_ahead, same_boot);
    }
}

/// PS7: the clock readings a pass starts from, passed in rather than read.
#[derive(Clone, Copy, Debug)]
pub struct Readings {
    pub mono_ms: u64,
    pub wall_ms: u64,
    pub clock_ahead: bool,
    pub same_boot: bool,
}

/// What one device holds for a pass (PS4).
pub struct Device<'a> {
    pub db: Database<'a>,
    /// SY27: the library folder, where `Backups/` is kept.
    pub root: &'a std::path::Path,
    pub lib: super::journal::Library,
    pub store: &'a mut super::device_store::DeviceStore,
    pub ks: &'a dyn super::device_store::Keystore,
    pub state: State,
    /// SP16, SY7: the platform's name for this device (cut to 64 characters).
    pub name: &'a str,
}

/// The application's store mutex is the authority for all access to its connection.
#[derive(Clone, Copy)]
pub enum Database<'a> {
    Store(&'a std::sync::Mutex<crate::store::Store>),
    #[cfg(test)]
    Test(&'a crate::store::Store),
}

pub enum DatabaseGuard<'a> {
    Store(std::sync::MutexGuard<'a, crate::store::Store>),
    #[cfg(test)]
    Test(&'a crate::store::Store),
}

impl std::ops::Deref for DatabaseGuard<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self {
            Self::Store(store) => store.conn(),
            #[cfg(test)]
            Self::Test(store) => store.conn(),
        }
    }
}

impl Database<'_> {
    pub fn lock(&self) -> Result<DatabaseGuard<'_>, Error> {
        match self {
            Self::Store(store) => store
                .lock()
                .map(DatabaseGuard::Store)
                .map_err(|_| Error::StoreLock),
            #[cfg(test)]
            Self::Test(store) => Ok(DatabaseGuard::Test(store)),
        }
    }
}

/// PS6: which budget stopped a pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stopped {
    Names,
    Devices,
    Bytes,
    Time,
}

/// PS4: what a pass did and what it left.
#[derive(Debug, Default)]
pub struct Report {
    pub names_listed: u64,
    pub bytes_read: u64,
    /// Paths set aside, with why (SP7: outside the layout, too large, a copy).
    pub set_aside: Vec<(String, String)>,
    pub trusted: Vec<DeviceId>,
    /// Peers whose device file was accepted with a new counter (SP16, SP18).
    pub accepted: Vec<DeviceId>,
    /// SP37 (4): peers whose change files were received this pass, with how many
    /// of their changes this device holds now.
    pub received: Vec<(DeviceId, u64)>,
    /// SP18: peers whose view was taken this pass, so their changes up to its
    /// `through` were not read one by one.
    pub viewed: Vec<DeviceId>,
    /// SP37 (5): the later fetches of bodies that received versions waited for.
    pub late: super::bodies::Late,
    /// SP37 (5), SY23: the blobs found damaged and the ones written again.
    pub objects: super::repair::Handled,
    /// SP37 (4): peers still ahead of this device after the pass: a change file
    /// not in storage yet, a chain that waits, or one the pass left for a budget.
    pub behind: Vec<DeviceId>,
    /// SP37 (3), SY34: identities membership doesn't hold whose device file or
    /// `enroll/` request checked out. Nothing in them is believed or kept.
    pub strangers: Vec<super::strangers::Stranger>,
    /// SY34: unknown identities past the 32 a pass looks at, which it didn't read.
    pub strangers_unread: u64,
    /// SP37 (3), SP18, SP26: each removed device's change files after its cutoff,
    /// listed and not applied, for the reader's Keep · Discard.
    pub tails: Vec<super::tails::Tail>,
    pub stopped: Option<Stopped>,
    /// PS6: bytes written to storage; they count against `Budgets::bytes` with the
    /// bytes read.
    pub bytes_written: u64,
    /// SP37 (9)–(10): what this pass published.
    pub published: Published,
    /// SP37 (9): local versions still unsent after the pass: they wait for a
    /// budget, a reservation's room, a hold's acknowledgement, or a body.
    pub unsent: u64,
    /// SP15 (1): why this device published nothing, when it found storage that
    /// it can't write beside.
    pub blocked: Option<Blocked>,
    /// SP37 (6), SY26: the reader's question, when one is open after the pass: what
    /// was counted. Nothing more is applied until it is answered.
    pub asking: Option<super::guard::Counts>,
    /// SY26, SY27: sync is paused (Stop syncing, or a restored backup), so nothing
    /// is received or applied.
    pub paused: bool,
    /// SP37 (6), SY27: why the pass took a backup under the lock, if it did.
    pub backup: Option<String>,
    /// PS4: steps not built yet are named, never silently skipped.
    pub not_built: &'static str,
}

/// SP37 (9)–(10): what one pass wrote to storage.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Published {
    /// Change files uploaded (SP14), by sequence, in the order they were written.
    pub changes: Vec<u64>,
    /// SP33: reservations and SP34: holds listed in the changes made this pass.
    pub reserved: u64,
    pub held: u64,
    /// SP9: blobs uploaded.
    pub blobs: u64,
    /// SP16: the counter of the device file written this pass.
    pub device_file: Option<u64>,
}

/// SP15 (1), SY7: storage shows this device's own files in a state it must not
/// publish beside. Nothing is numbered or written until it is clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// A change or device file of this ID newer than this device's marks: its
    /// device store was restored from an older copy. SY7 answers with a rotation
    /// (SP27), which isn't built yet.
    StorageAhead,
    /// A device file of this ID that carries another writer token (SY7).
    OtherWriter,
}

/// PS6: counts what a pass uses and says when a budget runs out.
pub(super) struct Meter<'b> {
    budgets: &'b Budgets,
    now: &'b dyn Fn() -> u64,
    start: u64,
    devices: u64,
}

impl Meter<'_> {
    pub(super) fn check(&self, report: &Report) -> Option<Stopped> {
        if report.names_listed > self.budgets.names {
            Some(Stopped::Names)
        } else if self.devices > self.budgets.devices {
            Some(Stopped::Devices)
        } else {
            // PS6: what a pass writes counts with what it reads.
            self.reading(report.bytes_read + report.bytes_written)
        }
    }

    pub(super) fn budgets(&self) -> &Budgets {
        self.budgets
    }

    /// The budgets a read can use up: bytes and time.
    pub(super) fn reading(&self, bytes_read: u64) -> Option<Stopped> {
        if bytes_read > self.budgets.bytes {
            Some(Stopped::Bytes)
        } else if (self.now)().saturating_sub(self.start) > self.budgets.elapsed_ms {
            Some(Stopped::Time)
        } else {
            None
        }
    }
}

/// SP7, PS6: every page of one directory, each listing counted against the name
/// budget; `None` when a budget ran out part-way.
pub(super) fn list_all<F: super::folder::Folder>(
    folder: &F,
    dir: &str,
    meter: &Meter<'_>,
    report: &mut Report,
) -> Result<Option<Vec<super::folder::Listed<F::Token>>>, Error> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = folder.list(dir, cursor.as_deref())?;
        report.names_listed += page.entries.len() as u64;
        all.extend(page.entries);
        if let Some(stop) = meter.check(report) {
            report.stopped = Some(stop);
            return Ok(None);
        }
        match page.next {
            Some(next) if cursor.as_deref() != Some(next.as_str()) => cursor = Some(next),
            _ => return Ok(Some(all)),
        }
    }
}

/// SP7: a file's bytes through `files::read_file`, or why it was set aside.
pub(super) fn read_bytes<F: super::folder::Folder>(
    folder: &F,
    entry: &super::folder::Listed<F::Token>,
    report: &mut Report,
) -> Result<Option<Vec<u8>>, Error> {
    read_bytes_within(folder, entry, None, report)
}

/// `read_bytes` held to `limit` as well as the slot's, when one is given (SY28).
pub(super) fn read_bytes_within<F: super::folder::Folder>(
    folder: &F,
    entry: &super::folder::Listed<F::Token>,
    limit: Option<u64>,
    report: &mut Report,
) -> Result<Option<Vec<u8>>, Error> {
    use super::files::Read;
    let read = match limit {
        Some(limit) => super::files::read_file_within(folder, entry, limit)?,
        None => super::files::read_file(folder, entry)?,
    };
    let why = match read {
        Read::Bytes(bytes) => {
            report.bytes_read += bytes.len() as u64;
            return Ok(Some(bytes));
        }
        Read::Outside => "outside the layout",
        Read::Candidate { .. } => "a candidate copy",
        Read::TooLarge => "over its limit",
        Read::Gone => "gone",
    };
    report.set_aside.push((entry.name.clone(), why.into()));
    Ok(None)
}

/// SP20 (2): the code enrollments among `heads` and the records they build on.
fn code_enrollments_below(
    records: &BTreeMap<Hash32, super::trust::Record>,
    heads: impl Iterator<Item = Hash32>,
) -> BTreeSet<Hash32> {
    use super::trust::Body;
    let mut seen = BTreeSet::new();
    let mut found = BTreeSet::new();
    let mut todo: Vec<Hash32> = heads.collect();
    while let Some(h) = todo.pop() {
        if !seen.insert(h) {
            continue;
        }
        let Some(record) = records.get(&h) else {
            continue;
        };
        if matches!(record.body, Body::Enroll { by: None, .. }) {
            found.insert(h);
        }
        todo.extend(record.prevs());
    }
    found
}

pub(super) fn save_state(device: &Device<'_>) -> Result<(), Error> {
    let db = device.db;
    let conn = db.lock()?;
    save_state_in(device, &conn)
}

pub(super) fn save_state_in(device: &Device<'_>, conn: &Connection) -> Result<(), Error> {
    let tx = super::journal::Unit::begin(conn)?;
    device.state.save(&tx, &device.lib.id)?;
    tx.commit()?;
    Ok(())
}

/// PS5, C30: the places between two steps of a pass, and inside step 6, where a test
/// may stop it, as a kill would, to see what the next pass makes of what was committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    /// The end of step `n`, after what it changed is saved.
    After(u8),
    /// Step 6: the store's write lock is taken.
    Locked,
    /// Step 6: the backup is taken, under the lock.
    BackedUp,
    /// Step 6: everything is applied and saved, and the lock's transaction is open.
    Applied,
    /// Step 6: the transaction has committed and the lock is released.
    Committed,
}

#[cfg(test)]
type Hook = Box<dyn FnMut(Point, &Connection) -> Result<(), Error>>;
#[cfg(test)]
thread_local! {
    pub(super) static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
}

/// A test's stop between two steps; nothing in a build that isn't a test.
#[cfg(test)]
pub(super) fn at(point: Point, conn: &Connection) -> Result<(), Error> {
    HOOK.with(|h| match h.borrow_mut().as_mut() {
        Some(hook) => hook(point, conn),
        None => Ok(()),
    })
}
#[cfg(not(test))]
#[inline(always)]
pub(super) fn at(_: Point, _: &Connection) -> Result<(), Error> {
    Ok(())
}

/// SP37 (1)–(6) and (9)–(10), PS4–PS7: one pass. It reads membership before any
/// device file (#122's crowding risk), saves `State` after each step that changed
/// it (PS5), and stops where a budget runs out (PS6). What isn't built yet is named
/// in the report's `not_built`.
pub fn run<F: super::folder::Folder>(
    device: &mut Device<'_>,
    folder: &mut F,
    readings: Readings,
    budgets: &Budgets,
    now: &dyn Fn() -> u64,
) -> Result<Report, Error> {
    if super::guard::paused(&*device.db.lock()?, &device.lib)? {
        return Ok(Report {
            paused: true,
            ..Report::default()
        });
    }
    let mut report = steps(device, folder, readings, budgets, now)?;
    // SP37 (4): the peers still ahead, whichever way the steps ended.
    for &peer in &report.trusted {
        if peer == device.lib.device || device.state.membership.quarantined.contains_key(&peer) {
            continue;
        }
        let target = device
            .store
            .library(&device.lib.id)
            .and_then(|l| l.floors.get(&peer.to_string()))
            .map_or(0, |f| f.s);
        if super::apply::seen(&*device.db.lock()?, &device.lib, peer)? < target {
            report.behind.push(peer);
        }
    }
    Ok(report)
}

fn steps<F: super::folder::Folder>(
    device: &mut Device<'_>,
    folder: &mut F,
    readings: Readings,
    budgets: &Budgets,
    now: &dyn Fn() -> u64,
) -> Result<Report, Error> {
    use super::device_file::{self, Accepted};
    use super::{membership, trust};
    let mut report = Report {
        not_built: "steps (7), (8) and (11); within step (3): what to keep between passes of an unknown identity's request and of a removed device's tail (item 128: nothing is kept, so a tail is read again each pass), the 8-request cap and the day's removal of old requests (SY34: they are the enrolled device's `enroll/` sweep with answering and approving, which are SP24's), and the reader’s Keep · Discard of a tail (SP26: later pass and UI work); within step (5): the reader's Try again for a quarantined object (`choice:obj.`, SP12: nothing here writes a choice record or applies one's `clears` to the saved quarantines, so a quarantine has no exit) and the Settings › Sync line that shows quarantines (a peer's `quarantined` list is read by no one), and the repair of books (Stage 4); within step (4): the open reservations and holds and the marks (SP35) a view carries, and a view found by listing when the device file names none (PS1 lists no directories); within steps (9)-(10): the accepted-by-all marks (SP29, so a hold's naming change waits), peers' reservations and holds in the ledger, books, SY7's rotation when storage is ahead (SP27), the device file's own view (compaction is P3b), its views and proofs lists, and the hour's re-upload of own and cached files (SP15)",
        ..Report::default()
    };
    let mut meter = Meter {
        budgets,
        now,
        start: now(),
        devices: 0,
    };
    device.state.resume(
        readings.mono_ms,
        readings.wall_ms,
        readings.clock_ahead,
        readings.same_boot,
    );
    let vouched_now = device.state.vouched.now() as i64;

    // (1) SP37, SY7, SP28: the device store holds this library's identity, the
    // writer token and readable marks.
    let library = device
        .store
        .library(&device.lib.id)
        .ok_or(Error::NoIdentity)?;
    if library.device_id()? != device.lib.device {
        return Err(Error::NoIdentity);
    }
    library.writer_id()?;
    super::frontier::stored_marks(library)?;
    let genesis = library
        .rest
        .get("genesis")
        .and_then(|v| v.as_str())
        .and_then(Hash32::parse)
        .ok_or(Error::NoIdentity)?;
    let own_head = library
        .rest
        .get("head")
        .and_then(|v| v.as_str())
        .and_then(Hash32::parse);
    let accepted = library.load_accepted()?;
    // SP9: bodies are named with the naming key, which the device store keeps.
    let naming = naming_key(library)?;
    save_state(device)?;
    at(Point::After(1), &*device.db.lock()?)?;

    // (2) SP37, SP20, SP21: libraries/ and trust/, then membership.
    if list_all(folder, "libraries", &meter, &mut report)?.is_none() {
        return Ok(report);
    }
    let Some(entries) = list_all(folder, "trust", &meter, &mut report)? else {
        return Ok(report);
    };
    // PS5, SY2: first-seen times are kept only for records still in trust/, so
    // records added and removed again can't grow the saved state without bound.
    // A record that comes back is timed afresh, which only makes it wait longer.
    let listed: BTreeSet<Hash32> = entries
        .iter()
        .filter_map(|e| {
            e.name
                .strip_prefix("trust/")
                .and_then(|n| n.strip_suffix(".json"))
                .and_then(Hash32::parse)
        })
        .collect();
    device
        .state
        .membership
        .first_seen
        .retain(|h, _| listed.contains(h));
    let mut records = BTreeMap::new();
    for entry in &entries {
        let Some(hash) = entry
            .name
            .strip_prefix("trust/")
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(Hash32::parse)
        else {
            report
                .set_aside
                .push((entry.name.clone(), "not a trust record".into()));
            continue;
        };
        // PS5: first-seen times already recorded are saved on every way out, or
        // a later pass would time those records from later (SP20 (1)).
        let read = read_bytes(folder, entry, &mut report);
        let Some(bytes) = (match read {
            Ok(bytes) => bytes,
            Err(e) => {
                save_state(device)?;
                return Err(e);
            }
        }) else {
            continue;
        };
        if let Some(stop) = meter.check(&report) {
            report.stopped = Some(stop);
            save_state(device)?;
            return Ok(report);
        }
        match trust::open(&bytes, &device.lib.id, &hash) {
            Ok(record) => {
                // SP20 (1): a record is timed from when this device first saw it.
                device
                    .state
                    .membership
                    .first_seen
                    .entry(hash)
                    .or_insert(vouched_now);
                records.insert(hash, record);
            }
            Err(e) => report.set_aside.push((entry.name.clone(), format!("{e}"))),
        }
    }
    let mut heads = device.state.membership.heads.clone();
    heads.insert(device.lib.device, own_head);
    // SP20 (2): a code enrollment counts once a live enrolled device's file
    // names a head that includes it, so membership is computed again until the
    // trusted devices' heads confirm nothing new. Each round confirms at least
    // one more record, so it ends.
    let membership = loop {
        let ms = &device.state.membership;
        let membership = membership::compute(&membership::Inputs {
            genesis,
            records: &records,
            first_seen: &ms.first_seen,
            confirmed: &ms.confirmed,
            checkpoint: &ms.checkpoint,
            held: &|_, _| None,
            accepted: &accepted,
            now_ms: vouched_now,
            me: Some(device.lib.device),
            quarantined: &ms.quarantined,
            heads: &heads,
        });
        // PS5: the first-seen times read this pass are saved even when storage
        // is stale (SP21), or a later pass would time those records from later.
        let membership = match membership {
            Ok(membership) => membership,
            Err(e) => {
                save_state(device)?;
                return Err(Error::Membership(e));
            }
        };
        let named = heads
            .iter()
            .filter(|(d, _)| membership.trusted(d).is_some())
            .filter_map(|(_, h)| *h);
        // Only a record membership is waiting to have confirmed: a chain that
        // does not reach the genesis, or an enrollment that is refused, is not
        // kept (so a peer's head can't grow the saved set).
        let new: Vec<Hash32> = code_enrollments_below(&records, named)
            .into_iter()
            .filter(|h| !device.state.membership.confirmed.contains(h))
            .filter(|h| {
                membership.verdict(h)
                    == Some(membership::Verdict::Waits(membership::Wait::Unconfirmed))
            })
            .collect();
        if new.is_empty() {
            break membership;
        }
        device.state.membership.confirmed.extend(new);
    };
    report.trusted = membership
        .state
        .members
        .keys()
        .filter(|d| membership.trusted(d).is_some())
        .copied()
        .collect();
    {
        let mut next = device.store.clone();
        next.library_mut(&device.lib.id)
            .ok_or(Error::NoIdentity)?
            .save_accepted(&membership, &records);
        next.save(device.ks)?;
        *device.store = next;
    }
    save_state(device)?;
    at(Point::After(2), &*device.db.lock()?)?;

    // (3) SP37, SP16, SP18: each trusted peer's device file, at most 32.
    let Some(entries) = list_all(folder, "devices", &meter, &mut report)? else {
        return Ok(report);
    };
    // SP18: the view each peer's accepted device file names, for step (4).
    let mut named_views: BTreeMap<DeviceId, Hash32> = BTreeMap::new();
    for peer in report.trusted.clone() {
        // SP30: a quarantined device's head stays frozen, so no later file of
        // its is accepted.
        if peer == device.lib.device || device.state.membership.quarantined.contains_key(&peer) {
            continue;
        }
        let path = device_file::device_path(&peer);
        let Some(entry) = entries.iter().find(|e| e.name == path) else {
            continue;
        };
        meter.devices += 1;
        if let Some(stop) = meter.check(&report) {
            report.stopped = Some(stop);
            break;
        }
        let Some(bytes) = read_bytes(folder, entry, &mut report)? else {
            continue;
        };
        if let Some(stop) = meter.check(&report) {
            report.stopped = Some(stop);
            break;
        }
        let Some(key) = membership.key(&peer) else {
            continue;
        };
        let opened = match device_file::open(&bytes, &device.lib.id, &peer, &key) {
            Ok(opened) => opened,
            Err(e) => {
                report.set_aside.push((path, format!("{e}")));
                continue;
            }
        };
        let floor = device
            .store
            .library(&device.lib.id)
            .and_then(|l| l.floors.get(&peer.to_string()))
            .map(|f| f.counter);
        // SP16: overflow parts live in the peer's own directory, listed only
        // when a file newer than the floor names some.
        let parts = if opened.overflow.is_empty() || floor >= Some(opened.counter) {
            Vec::new()
        } else {
            match list_all(folder, &format!("devices/{peer}"), &meter, &mut report)? {
                Some(parts) => parts,
                None => break,
            }
        };
        // PS6: each part's read is budgeted before it's made, so a file naming
        // many parts stops the pass after at most one part past the budget.
        let part_bytes = std::cell::Cell::new(0u64);
        let halted = std::cell::Cell::new(None);
        let base = report.bytes_read;
        let fetch = |part: &str| -> Option<Vec<u8>> {
            if let Some(stop) = meter.reading(base + part_bytes.get()) {
                halted.set(Some(stop));
                return None;
            }
            let listed = parts.iter().find(|e| e.name == part)?;
            match super::files::read_file(folder, listed).ok()? {
                super::files::Read::Bytes(b) => {
                    part_bytes.set(part_bytes.get() + b.len() as u64);
                    Some(b)
                }
                _ => None,
            }
        };
        let accepted = device_file::accept(
            device.ks,
            device.store,
            &device.lib.id,
            &peer,
            &key,
            &bytes,
            &fetch,
        );
        report.bytes_read += part_bytes.get();
        if let Some(stop) = halted.get() {
            report.stopped = Some(stop);
            break;
        }
        match accepted {
            Ok(Accepted::New(file, lists)) => {
                // SY23: what the peer found damaged is checked in step (5).
                device.state.objects.hint(&naming, lists.get("refused"));
                // SP16: and a repair it lists is first seen now, by this device's time.
                let seen = device.state.vouched.now() as i64;
                device
                    .state
                    .objects
                    .see_repairs(&naming, lists.get("repairs"), seen);
                device
                    .state
                    .heard
                    .saw_counter(peer, file.counter, &device.state.vouched);
                device.state.membership.heads.insert(peer, file.fields.head);
                named_views.extend(file.fields.view.map(|v| (peer, v)));
                report.accepted.push(peer);
            }
            // PS5: a crash after `accept` saved the floor but before the state
            // was saved loses the head; the file at the floor's own counter is
            // the one accepted, so its head is taken again.
            // Its `refused` entries are not: the file is seen every pass, and a
            // report is taken only from a new counter (`repair::Objects::hint`).
            Ok(Accepted::Stale) => {
                if floor == Some(opened.counter) {
                    device
                        .state
                        .membership
                        .heads
                        .insert(peer, opened.fields.head);
                    named_views.extend(opened.fields.view.map(|v| (peer, v)));
                }
            }
            Err(e) => report.set_aside.push((path, format!("{e}"))),
        }
        if let Some(stop) = meter.check(&report) {
            report.stopped = Some(stop);
            break;
        }
    }
    // PS5, SP32: catch Heard up with each peer's stored floor without
    // refreshing its time, so a crash after `accept` saved the floor but before
    // `Heard` was saved can only make this device out of touch sooner.
    if let Some(library) = device.store.library(&device.lib.id) {
        for (peer, floor) in &library.floors {
            if let Some(peer) = DeviceId::parse(peer) {
                device.state.heard.catch_up_counter(peer, floor.counter);
            }
        }
    }
    save_state(device)?;
    // SP37 (3), SY34: the identities membership doesn't hold, then the removed
    // devices' tails (SP18, SP26). Neither saves anything (PS5).
    if report.stopped.is_none() {
        super::strangers::read(
            &device.lib.id,
            folder,
            &membership,
            &entries,
            &meter,
            &mut report,
        )?;
    }
    if report.stopped.is_none() {
        super::tails::read(
            &device.lib.id,
            &device.lib.device,
            folder,
            &membership,
            &meter,
            &mut report,
        )?;
    }
    at(Point::After(3), &*device.db.lock()?)?;
    let mut blobs = None;
    let mut runs = Vec::new();
    if report.stopped.is_none() {
        receive_changes(
            device,
            folder,
            &membership,
            &naming,
            &named_views,
            &meter,
            &mut report,
            &mut blobs,
            &mut runs,
        )?;
    }
    at(Point::After(4), &*device.db.lock()?)?;
    // SP37 (5): the bodies received versions waited for, once storage has them.
    if report.stopped.is_none() {
        super::bodies::fetch_waiting(device, folder, &meter, &mut report, &mut blobs, &naming)?;
    }
    // SP37 (5), SY23: blobs a live version names that storage lost or damaged.
    if report.stopped.is_none() {
        let now = device.state.vouched.now() as i64;
        super::repair::repair(
            device,
            folder,
            &meter,
            &mut report,
            &mut blobs,
            &naming,
            now,
        )?;
    }
    save_state(device)?;
    at(Point::After(5), &*device.db.lock()?)?;
    // SP37 (6): small things first, under the store's lock. A budget that ran out in
    // (4) or (5) stops the pass after what step 6 has applied (SY2).
    super::applying::apply_all(
        device,
        &mut report,
        &naming,
        runs,
        &membership,
        readings.wall_ms as i64,
    )?;
    report.late.waiting = super::bodies::waiting(device)?;
    at(Point::After(6), &*device.db.lock()?)?;
    // SP37 (9): a budget that ran out earlier stops the pass where it is.
    if report.stopped.is_none() && !report.paused && report.asking.is_none() {
        super::publish::publish(
            device,
            folder,
            &naming,
            &meter,
            &mut report,
            &mut blobs,
            &entries,
        )?;
    }
    Ok(report)
}

/// SP9, SP28: the library's naming key, 32 bytes, kept in the device store.
fn naming_key(library: &super::device_store::LibraryState) -> Result<[u8; 32], Error> {
    library
        .rest
        .get("namingKey")
        .and_then(|v| v.as_str())
        .and_then(super::ids::b64url_decode)
        .and_then(|b| b.try_into().ok())
        .ok_or(Error::NoIdentity)
}

/// SY28: a version's record type limit on its body, when its key says which; and
/// whether the size it declares is past it, so the blob is never fetched.
pub(super) fn body_limit(version: &serde_json::Value) -> Option<u64> {
    version["key"]
        .as_str()
        .and_then(super::record::Key::parse)
        .map(|(key, _)| key.kind().body_limit())
}

pub(super) fn body_over_limit(version: &serde_json::Value) -> bool {
    body_limit(version)
        .zip(version["body"]["size"].as_u64())
        .is_some_and(|(limit, size)| size > limit)
}

/// SP37 (4), SP18, PS6: for each trusted peer whose accepted device file names a
/// change this device doesn't hold: its view when it is needed (`views`), then its
/// change files in order, each opened and checked, with the blobs its versions name
/// that storage has now (a body not there yet waits for step 5). What it reads is
/// kept in `runs`, and step (6) (`applying`) applies it under the store's lock:
/// `chain::receive_run` checks each run against the peer's floor there, after the
/// view when there is one. While sync is paused or the reader is asked, nothing is
/// read: nothing would be applied (SY26).
#[allow(clippy::too_many_arguments)]
fn receive_changes<F: super::folder::Folder>(
    device: &mut Device<'_>,
    folder: &F,
    membership: &super::membership::Membership,
    naming: &[u8; 32],
    named_views: &BTreeMap<DeviceId, Hash32>,
    meter: &Meter<'_>,
    report: &mut Report,
    blobs: &mut Option<BTreeMap<String, super::folder::Listed<F::Token>>>,
    runs: &mut Vec<super::applying::Run>,
) -> Result<(), Error> {
    use super::{apply, chain, device_file, views};
    // PS5: a removed device's note of a view isn't kept.
    let trusted = report.trusted.clone();
    device.state.views.peers.retain(|d, _| trusted.contains(d));
    // PS5: a view an earlier pass was landing is finished first, ahead or not.
    if views::finish_landings(device, folder, meter, report, membership, naming)? {
        return Ok(());
    }
    // SY26, SY27: a pause or an open question stops what is applied, so what would be
    // read is left in storage, which holds it.
    if super::guard::stalled(&*device.db.lock()?, &device.lib)? {
        return Ok(());
    }
    for peer in trusted {
        if peer == device.lib.device || device.state.membership.quarantined.contains_key(&peer) {
            continue;
        }
        let Some(target) = device
            .store
            .library(&device.lib.id)
            .and_then(|l| l.floors.get(&peer.to_string()))
            .map(|f| f.s)
        else {
            continue;
        };
        let have = apply::seen(&*device.db.lock()?, &device.lib, peer)?;
        let Some(key) = membership.key(&peer).filter(|_| have < target) else {
            continue;
        };
        // SY28: a peer this device has stopped receiving from costs the pass
        // nothing; it stays in `behind`.
        if apply::stopped(&*device.db.lock()?, &device.lib, peer)? {
            continue;
        }
        let floor = device_file::floor_of(device.store, &device.lib.id, &peer)?;
        // SP18: the view, when what this device has applied is older than its
        // `through`. One that can't be used is set aside and the change files are
        // read as before.
        let mut taken = None;
        if let Some(named) = named_views.get(&peer) {
            match views::open(
                device, folder, meter, report, blobs, naming, &peer, &key, named, have,
            )? {
                views::Got::Ready(opened) => taken = Some(*opened),
                views::Got::Skip => {}
                // #229 (2): this peer waits for a pass with room; the next is read.
                views::Got::Wait => continue,
                views::Got::Halt => return Ok(()),
            }
        }
        let start = taken.as_ref().map_or(have, |o| o.view.through.s);
        // SP18: a run reaches the lowest checkpoint it has not passed, however
        // long that takes, or `receive_run` would wait on it for ever.
        let lowest = floor
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| *s > have)
            .min()
            .unwrap_or(0);
        // #229 (1): a budget that ran out while the view was read stops the pass
        // after the view is received, when it alone reaches the checkpoint: the
        // bodies fetched so far come with it, and the rest wait for step 5 (SY28).
        // Otherwise the next pass would read the same view again, for ever.
        let stop = report.stopped.or_else(|| meter.check(report));
        let listing = match stop {
            Some(stop) => {
                report.stopped = Some(stop);
                None
            }
            None => list_all(folder, &format!("changes/{peer}"), meter, report)?,
        };
        let Some(listing) = listing else {
            if let Some(opened) = taken.filter(|o| o.view.through.s >= lowest) {
                runs.push(super::applying::Run {
                    peer,
                    key,
                    have,
                    floor,
                    last_sig: spine_mark(&opened),
                    taken: Some(opened),
                    files: Vec::new(),
                });
            }
            return Ok(());
        };
        let listing: BTreeMap<_, _> = listing.into_iter().map(|e| (e.name.clone(), e)).collect();
        let mut files = Vec::new();
        let mut last_sig = None;
        let mut run_bytes = 0u64;
        // A budget that runs out mid-run still lets what was read be received: a
        // body not fetched waits for step 5 (SY28), so the pass moves on.
        let mut halted = false;
        'run: for seq in start + 1..=target {
            let path = chain::change_path(&peer, seq);
            let Some(entry) = listing.get(&path) else {
                break;
            };
            let Some(bytes) = read_bytes(folder, entry, report)? else {
                break;
            };
            run_bytes += bytes.len() as u64;
            let change = match chain::open_change(&bytes, &device.lib.id, &peer, &key) {
                Ok(change) => change,
                Err(e) => {
                    report.set_aside.push((path, format!("{e}")));
                    break;
                }
            };
            let mut bodies = Vec::new();
            let mut stop = meter.check(report);
            for version in &change.versions {
                if stop.is_some() {
                    break;
                }
                let now = device.state.vouched.now() as i64;
                match fetch_body(
                    folder,
                    meter,
                    report,
                    blobs,
                    naming,
                    &mut device.state.objects,
                    now,
                    version,
                )? {
                    // PS6: a damaged read counts its bytes like a good one, so the
                    // meter is checked after every fetch, whatever it came to.
                    Body::Skip => {}
                    Body::Halt => {
                        halted = true;
                        break;
                    }
                    Body::Got(body) => bodies.push(body),
                }
                stop = meter.check(report);
            }
            last_sig = Some(SignedMark {
                s: change.seq,
                h: change.hash,
                sig: super::ids::b64url_encode(&change.sig),
            });
            files.push((bytes, bodies));
            if halted || stop.is_some() {
                halted = true;
                report.stopped = report.stopped.or(stop);
                break 'run;
            }
            if run_bytes > meter.budgets().run_bytes && seq >= lowest {
                break;
            }
        }
        // SP16: a view alone is vouched for by its own last spine entry.
        if last_sig.is_none() {
            last_sig = taken.as_ref().and_then(spine_mark);
        }
        // SP37 (4), (6): what was read waits for step 6, which keeps the signature of
        // the run's last change before it applies the run (SP16).
        if taken.is_some() || !files.is_empty() {
            runs.push(super::applying::Run {
                peer,
                key,
                have,
                floor,
                last_sig,
                taken,
                files,
            });
        }
        if halted {
            return Ok(());
        }
    }
    Ok(())
}

/// SP16: a view alone is vouched for by its own last spine entry.
fn spine_mark(opened: &super::views::Opened) -> Option<SignedMark> {
    opened.view.spine.last().map(|e| SignedMark {
        s: e.s,
        h: e.h,
        sig: super::ids::b64url_encode(&e.sig),
    })
}

/// SP37 (4), (6): what a peer's receive came to: the report, and the floor's checkpoints
/// that no later change need be kept for.
pub(super) fn settle(
    device: &mut Device<'_>,
    report: &mut Report,
    peer: DeviceId,
    have: u64,
) -> Result<(), Error> {
    let now_held = super::apply::seen(&*device.db.lock()?, &device.lib, peer)?;
    if now_held > have {
        report.received.push((peer, now_held));
        super::device_file::prune_floors(device.ks, device.store, &device.lib.id, &peer, now_held)?;
    }
    Ok(())
}

/// SY28: what fetching one version's body came to.
pub(super) enum Body {
    /// Nothing to read: no body, past its type's limit, or not in storage yet.
    Skip,
    Got(Vec<u8>),
    /// A budget ran out while listing `blobs/`.
    Halt,
}

/// SP9, SY28: the body a version names, from `blobs/` under its keyed name, read no
/// further than its record type allows (whatever size the version declared). `blobs/`
/// is listed once per pass, when a body is first wanted. The bytes are checked
/// against the plain hash the version names (SY23): a body that fails, or is over
/// its limit, is set aside and kept in `objects` as refused, and is not read again
/// until `stat` shows another size or the retry hour has passed (`repair::RETRY_MS`).
#[allow(clippy::too_many_arguments)]
pub(super) fn fetch_body<F: super::folder::Folder>(
    folder: &F,
    meter: &Meter<'_>,
    report: &mut Report,
    blobs: &mut Option<BTreeMap<String, super::folder::Listed<F::Token>>>,
    naming: &[u8; 32],
    objects: &mut super::repair::Objects,
    now: i64,
    version: &serde_json::Value,
) -> Result<Body, Error> {
    use super::repair::{read_blob, Blob};
    let Some(hash) = version["body"]["hash"].as_str().and_then(Hash32::parse) else {
        return Ok(Body::Skip);
    };
    // SY28: a body past its record type's limit is never fetched.
    if body_over_limit(version) {
        return Ok(Body::Skip);
    }
    // SP16, SY23: a quarantined object is not fetched by this device by itself.
    let name = super::crypto::blob_name(naming, &hash);
    if objects.is_quarantined(&name) {
        return Ok(Body::Skip);
    }
    if blobs.is_none() {
        let Some(listed) = list_all(folder, "blobs", meter, report)? else {
            return Ok(Body::Halt);
        };
        *blobs = Some(listed.into_iter().map(|e| (e.name.clone(), e)).collect());
    }
    // SP9: a body is stored under its keyed name.
    let Some(blob) = blobs.as_ref().and_then(|b| b.get(&format!("blobs/{name}"))) else {
        return Ok(Body::Skip);
    };
    // SY23: what stat says of a blob found damaged before decides whether it is read.
    let Some(size) = folder.stat(&blob.token)? else {
        return Ok(Body::Skip);
    };
    if objects.leave(&name, &hash, size, now) {
        return Ok(Body::Skip);
    }
    Ok(
        match read_blob(
            folder,
            blob,
            &hash,
            body_limit(version).unwrap_or(u64::MAX),
            report,
        )? {
            Blob::Good(body) => {
                objects.good(&name, now);
                Body::Got(body)
            }
            Blob::Damaged => {
                if objects.damaged(&name, &hash, size, now) {
                    report.objects.quarantined.push(name.clone());
                }
                if !report.objects.refused.contains(&name) {
                    report.objects.refused.push(name);
                }
                Body::Skip
            }
            Blob::Other => Body::Skip,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::sync::record::Entry;
    use serde_json::{json, Value};

    fn setup() -> (Store, Id16) {
        (Store::open_in_memory().unwrap(), Id16([1; 16]))
    }
    fn save(store: &mut Store, lib: &Id16, state: &State) {
        // Store exposes a connection; an unchecked transaction uses the same database.
        let tx = store.conn().unchecked_transaction().unwrap();
        state.save(&tx, lib).unwrap();
        tx.commit().unwrap();
    }
    #[test]
    fn state_round_trips_through_the_database() {
        let (mut store, lib) = setup();
        let d = Id16([2; 16]);
        let h = Hash32([3; 32]);
        let e = Entry {
            device: d,
            seq: 7,
            hash: h,
        };
        let id = json!({"device": d, "seq": 7, "index": 1});
        let change = json!({"device": d, "seq": 7, "hash": h});
        let mark = json!({"s": 7, "h": h});
        let reservation =
            json!({"item":{"kind":"Blob","name":h,"size":9},"first_seen":10,"_claimed":true});
        let holding = json!({"item":{"kind":"Book","name":h,"hash":h,"size":11,"for_key":"setting:theme"},"claimed":true,"change":change,"accepted_at":12,"naming":[change,e]});
        let ledger =
            json!({"reservations":[[id,reservation]],"holds":[[id,holding]],"last":[[d,mark]]});
        let weeks = json!({"entries":[[e,[["setting:theme",[[{"kind":"Blob","name":h},true]]]]]]});
        let heard = json!({"counters":[[d,[3,4]]],"applied":[[d,5]]});
        let marks = json!({"own":[[e,6]],"in_view":[e],"reported":[[e,[d]]]});
        let ages = json!({"first_seen":[[e,8]],"reported":[[[e,d],[9,10]]]});
        let vouched =
            json!({"total_ms":100,"last_mono_ms":42,"last_wall_ms":300,"untrusted_wall":true});
        let membership = json!({"first_seen":[[h,-2]],"confirmed":[h],"checkpoint":[h],"quarantined":[[d,mark]],"heads":[[d,h]]});
        let views = json!({"peers":[[d,{"hash":h,"through":7,"tries":2,"refused":false}]],"landing":[[d,{"hash":h,"gen":3,"through":7,"tries":1}]]});
        let objects = json!({"refused":{"aa":{"hash":"bb","size":9,"at":3}},"repaired":{"cc":{"hash":"dd","at":4,"done":false}},"hints":{"ee":"ff"},"checked":{"gg":5},"listed":6,"watched":{"hh":{"seen":7,"good":true}},"quarantined":{"ii":{"at":8,"q":null},"jj":{"at":9,"q":3}}});
        // A row saved before the quarantine existed still loads, with none.
        let old: crate::sync::repair::Objects = serde_json::from_value(
            json!({"refused":{},"repaired":{},"hints":{},"checked":{},"listed":null}),
        )
        .unwrap();
        assert!(old.watched.is_empty() && old.quarantined.is_empty());
        let state = State {
            ledger: serde_json::from_value(ledger.clone()).unwrap(),
            weeks: serde_json::from_value(weeks.clone()).unwrap(),
            heard: serde_json::from_value(heard.clone()).unwrap(),
            marks: serde_json::from_value(marks.clone()).unwrap(),
            ages: serde_json::from_value(ages.clone()).unwrap(),
            vouched: serde_json::from_value(vouched.clone()).unwrap(),
            membership: serde_json::from_value(membership.clone()).unwrap(),
            sigs: Default::default(),
            views: serde_json::from_value(views.clone()).unwrap(),
            objects: serde_json::from_value(objects.clone()).unwrap(),
            started: true,
        };
        save(&mut store, &lib, &state);
        let loaded = State::load(store.conn(), &lib).unwrap();
        for (actual, expected) in [
            (serde_json::to_value(loaded.ledger).unwrap(), ledger),
            (serde_json::to_value(loaded.weeks).unwrap(), weeks),
            (serde_json::to_value(loaded.heard).unwrap(), heard),
            (serde_json::to_value(loaded.marks).unwrap(), marks),
            (serde_json::to_value(loaded.ages).unwrap(), ages),
            (serde_json::to_value(loaded.vouched).unwrap(), vouched),
            (serde_json::to_value(loaded.membership).unwrap(), membership),
            (serde_json::to_value(loaded.views).unwrap(), views),
            (serde_json::to_value(loaded.objects).unwrap(), objects),
        ] {
            assert_eq!(actual, expected);
        }
    }
    #[test]
    fn a_restart_keeps_a_deletions_age_and_a_witness_timeout() {
        let (mut store, lib) = setup();
        let mut state = State::default();
        let d = Id16([2; 16]);
        let e = Entry {
            device: d,
            seq: 1,
            hash: Hash32([3; 32]),
        };
        state.vouched.tick(100, 1000);
        state.vouched.tick(200, 1100);
        state.ages.saw(e, state.vouched.now());
        state.heard.saw_counter(d, 1, &state.vouched);
        state.vouched.tick(300, 1200);
        save(&mut store, &lib, &state);
        for same_boot in [true, false] {
            let mut loaded = State::load(store.conn(), &lib).unwrap();
            loaded.resume(if same_boot { 400 } else { 10 }, 1300, false, same_boot);
            assert_eq!(loaded.ages.own_age(&e, loaded.vouched.now()), Some(200));
            let heard: Value = serde_json::to_value(&loaded.heard).unwrap();
            assert_eq!(heard["counters"][0][1][1], 100);
            assert_eq!(
                loaded.vouched.now() - heard["counters"][0][1][1].as_u64().unwrap(),
                200
            );
        }
    }
    #[test]
    fn membership_inputs_survive_a_restart() {
        let (mut store, lib) = setup();
        let mut state = State::default();
        let h = Hash32([9; 32]);
        state.membership.first_seen.insert(h, 123);
        save(&mut store, &lib, &state);
        assert_eq!(
            State::load(store.conn(), &lib)
                .unwrap()
                .membership
                .first_seen
                .get(&h),
            Some(&123)
        );
    }

    #[test]
    fn a_first_pass_starts_the_clock_now() {
        // PS5, SY17: no saved clock yet; resuming must not count the time since
        // the Unix epoch as elapsed, or every unheard witness looks silent for
        // decades and SP32 holds changes at once.
        let (store, lib) = setup();
        let mut state = State::load(store.conn(), &lib).unwrap();
        let wall = 1_790_000_000_000;
        state.resume(5_000, wall, false, false);
        assert_eq!(state.vouched.now(), 0);
        state.resume(5_000 + 60_000, wall + 60_000, false, true);
        assert_eq!(state.vouched.now(), 60_000);
    }

    mod run {
        use super::super::*;
        use crate::sync::folder::Folder;
        use crate::sync::testkit::{self, KitDevice};
        use std::cell::Cell;

        // Past the real clock: the kit's changes are stamped with it (SY10 holds a
        // version whose clock is ahead of the reader's).
        const READ: Readings = Readings {
            mono_ms: 1_000,
            wall_ms: 1_900_000_000_000,
            clock_ahead: false,
            same_boot: false,
        };

        fn pass(kd: &mut KitDevice, budgets: &Budgets) -> (Report, State) {
            pass_at(kd, READ, budgets)
        }

        #[test]
        fn store_mutex_covers_backup_and_apply_but_not_folder_io() {
            use crate::sync::folder::{self, Page, Read};
            use std::sync::{Arc, Mutex};
            struct Checked {
                inner: folder::View,
                db: Arc<Mutex<crate::store::Store>>,
            }
            impl Folder for Checked {
                type Token = <folder::View as Folder>::Token;
                fn list(
                    &self,
                    dir: &str,
                    cursor: Option<&str>,
                ) -> std::io::Result<Page<Self::Token>> {
                    assert!(self.db.try_lock().is_ok(), "lock held during list");
                    self.inner.list(dir, cursor)
                }
                fn stat(&self, token: &Self::Token) -> std::io::Result<Option<u64>> {
                    assert!(self.db.try_lock().is_ok(), "lock held during stat");
                    self.inner.stat(token)
                }
                fn read(&self, token: &Self::Token, limit: Option<u64>) -> std::io::Result<Read> {
                    assert!(self.db.try_lock().is_ok(), "lock held during read");
                    self.inner.read(token, limit)
                }
                fn write(&mut self, path: &str, bytes: &[u8]) -> std::io::Result<()> {
                    assert!(self.db.try_lock().is_ok(), "lock held during write");
                    self.inner.write(path, bytes)
                }
                fn remove(&mut self, token: &Self::Token) -> std::io::Result<()> {
                    assert!(self.db.try_lock().is_ok(), "lock held during remove");
                    self.inner.remove(token)
                }
            }
            let mut kit = testkit::library(2);
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("remote"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
            let inner = kit.folder.view(&kit.devices[0].lib.device.to_string());
            let kd = &mut kit.devices[0];
            kd.db
                .save_annotation(&highlight("book", Some("local"), 1_760_000_002_000))
                .unwrap();
            let db = Arc::new(Mutex::new(std::mem::replace(
                &mut kd.db,
                crate::store::Store::open_in_memory().unwrap(),
            )));
            let state = State::load(db.lock().unwrap().conn(), &kd.lib.id).unwrap();
            let locked = Arc::clone(&db);
            let points = Arc::new(Mutex::new(Vec::new()));
            let observed = Arc::clone(&points);
            HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |point, _| {
                    if matches!(point, Point::BackedUp | Point::Applied) {
                        assert!(locked.try_lock().is_err());
                        observed.lock().unwrap().push(point);
                    }
                    Ok(())
                }))
            });
            let mut device = Device {
                db: Database::Store(&db),
                root: kd.root.path(),
                lib: kd.lib,
                store: &mut kd.store,
                ks: &kd.ks,
                state,
                name: "Test Mac",
            };
            let mut folder = Checked {
                inner,
                db: Arc::clone(&db),
            };
            let result = run(&mut device, &mut folder, READ, &Budgets::sy2(), &|| 0);
            HOOK.with(|hook| *hook.borrow_mut() = None);
            let report = result.unwrap();
            assert!(!report.received.is_empty());
            assert_eq!(
                *points.lock().unwrap(),
                vec![Point::BackedUp, Point::Applied]
            );
        }

        #[test]
        fn failure_before_step_six_commit_restores_database_and_state() {
            let mut kit = testkit::library(2);
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("remote"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
            let peer = kit.devices[1].lib.device;
            let kd = &mut kit.devices[0];
            let state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let mut device = Device {
                db: Database::Test(&kd.db),
                root: kd.root.path(),
                lib: kd.lib,
                store: &mut kd.store,
                ks: &kd.ks,
                state,
                name: "Test Mac",
            };
            HOOK.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(|point, _| {
                    if point == Point::Applied {
                        return Err(Error::Folder(std::io::Error::other(
                            "injected before commit",
                        )));
                    }
                    Ok(())
                }))
            });
            let failed = run(&mut device, &mut kd.folder, READ, &Budgets::sy2(), &|| 0);
            HOOK.with(|hook| *hook.borrow_mut() = None);
            assert!(failed.is_err());
            assert!(kd.db.annotations("book").unwrap().is_empty());
            assert_eq!(
                crate::sync::apply::seen(kd.db.conn(), &kd.lib, peer).unwrap(),
                0
            );
            let saved = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            assert_eq!(
                serde_json::to_value(&saved.views).unwrap(),
                serde_json::to_value(&device.state.views).unwrap()
            );
            let report = run(&mut device, &mut kd.folder, READ, &Budgets::sy2(), &|| 0).unwrap();
            assert_eq!(report.received.len(), 1);
            assert_eq!(kd.db.annotations("book").unwrap().len(), 1);
        }

        #[test]
        fn pausing_during_folder_read_stops_apply_revert_and_publish() {
            use crate::sync::folder::{self, Page, Read};
            use std::sync::{
                atomic::{AtomicBool, AtomicUsize, Ordering},
                Arc, Mutex,
            };
            struct Pausing {
                inner: folder::View,
                db: Arc<Mutex<crate::store::Store>>,
                paused: AtomicBool,
                writes: AtomicUsize,
            }
            impl Folder for Pausing {
                type Token = <folder::View as Folder>::Token;
                fn list(
                    &self,
                    dir: &str,
                    cursor: Option<&str>,
                ) -> std::io::Result<Page<Self::Token>> {
                    self.inner.list(dir, cursor)
                }
                fn stat(&self, token: &Self::Token) -> std::io::Result<Option<u64>> {
                    self.inner.stat(token)
                }
                fn read(&self, token: &Self::Token, limit: Option<u64>) -> std::io::Result<Read> {
                    let result = self.inner.read(token, limit)?;
                    if !self.paused.swap(true, Ordering::SeqCst) {
                        self.db
                            .lock()
                            .unwrap()
                            .conn()
                            .execute("UPDATE sync_libraries SET state = 'paused'", [])
                            .unwrap();
                    }
                    Ok(result)
                }
                fn write(&mut self, path: &str, bytes: &[u8]) -> std::io::Result<()> {
                    self.writes.fetch_add(1, Ordering::SeqCst);
                    self.inner.write(path, bytes)
                }
                fn remove(&mut self, token: &Self::Token) -> std::io::Result<()> {
                    self.writes.fetch_add(1, Ordering::SeqCst);
                    self.inner.remove(token)
                }
            }
            let mut kit = testkit::library(3);
            kit.devices[1]
                .db
                .save_annotation(&highlight(
                    "book",
                    Some("already applied"),
                    1_760_000_001_000,
                ))
                .unwrap();
            kit.devices[1].publish_pending();
            pass(&mut kit.devices[0], &Budgets::sy2());
            let peer = kit.devices[1].lib.device;
            let mut new = highlight("book", Some("must wait"), 1_760_000_002_000);
            new.id = "2b3c4d5e-6f7a-4b1c-9d2e-4f5a6b7c8d9e".into();
            kit.devices[2].db.save_annotation(&new).unwrap();
            kit.devices[2].publish_pending();
            let inner = kit.folder.view(&kit.devices[0].lib.device.to_string());
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            state.membership.quarantined.insert(peer, None);
            save_raw(kd, &state);
            let db = Arc::new(Mutex::new(std::mem::replace(
                &mut kd.db,
                crate::store::Store::open_in_memory().unwrap(),
            )));
            let mut folder = Pausing {
                inner,
                db: Arc::clone(&db),
                paused: AtomicBool::new(false),
                writes: AtomicUsize::new(0),
            };
            let mut device = Device {
                db: Database::Store(&db),
                root: kd.root.path(),
                lib: kd.lib,
                store: &mut kd.store,
                ks: &kd.ks,
                state,
                name: "Test Mac",
            };
            let report = run(&mut device, &mut folder, READ, &Budgets::sy2(), &|| 0).unwrap();
            assert!(report.paused);
            assert!(folder.paused.load(Ordering::SeqCst));
            assert_eq!(folder.writes.load(Ordering::SeqCst), 0);
            let db = db.lock().unwrap();
            let rows = db.annotations("book").unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].note.as_deref(), Some("already applied"));
            let late: i64 = db
                .conn()
                .query_row("SELECT COUNT(*) FROM sync_late", [], |r| r.get(0))
                .unwrap();
            assert_eq!(late, 0, "the quarantine did not revert during the pause");
        }

        #[test]
        fn pausing_after_apply_stops_publication() {
            let mut kit = testkit::library(2);
            let kd = &mut kit.devices[0];
            kd.db
                .save_annotation(&highlight("book", Some("local"), 1_760_000_001_000))
                .unwrap();
            HOOK.with(|h| {
                *h.borrow_mut() = Some(Box::new(|point, conn| {
                    if point == Point::After(6) {
                        conn.execute("UPDATE sync_libraries SET state = 'paused'", [])?;
                    }
                    Ok(())
                }))
            });
            let (report, _) = pass(kd, &Budgets::sy2());
            HOOK.with(|h| *h.borrow_mut() = None);
            assert!(report.paused);
            assert!(report.published.changes.is_empty());
            assert_eq!(kd.store.library(&kd.lib.id).unwrap().seq, 0);
            assert!(!crate::sync::journal::unsent(kd.db.conn(), &kd.lib)
                .unwrap()
                .is_empty());
        }

        #[test]
        fn approved_pending_key_does_not_approve_a_newer_peer_version() {
            use crate::sync::{
                apply::{self, Batch},
                files::{self, Read},
                guard,
            };
            let mut kit = testkit::library(3);
            let mut batches = Vec::new();
            for i in 1..=2 {
                let kd = &mut kit.devices[i];
                let text = if i == 1 { "approved" } else { "newer" };
                kd.db
                    .save_annotation(&highlight("book", Some(text), 1_760_000_001_000 + i as i64))
                    .unwrap();
                kd.publish_pending().unwrap();
                let path = crate::sync::chain::change_path(&kd.lib.device, 1);
                let entry = kd
                    .folder
                    .list(&format!("changes/{}", kd.lib.device), None)
                    .unwrap()
                    .entries
                    .into_iter()
                    .find(|e| e.name == path)
                    .unwrap();
                let Read::Bytes(bytes) = files::read_file(&kd.folder, &entry).unwrap() else {
                    panic!("change unavailable")
                };
                let change = crate::sync::chain::open_change(
                    &bytes,
                    &kd.lib.id,
                    &kd.lib.device,
                    &kd.key.public(),
                )
                .unwrap();
                let mut batch = Batch {
                    device: kd.lib.device,
                    seq: 1,
                    hash: change.hash,
                    versions: change.versions,
                    bodies: vec![],
                };
                for version in &mut batch.versions {
                    version["clock"] =
                        serde_json::json!([READ.wall_ms - (3 - i as u64) * 1_000, 0]);
                }
                batches.push(batch);
            }
            let kd = &kit.devices[0];
            for batch in &batches {
                apply::receive(kd.db.conn(), &kd.lib, batch, READ.wall_ms as i64).unwrap();
            }
            let key = batches[0]
                .versions
                .iter()
                .find_map(|v| v["key"].as_str().filter(|k| k.starts_with("annotation:")))
                .unwrap();
            let approved = (batches[0].device.to_string(), 1, key.to_string());
            guard::ask(
                kd.db.conn(),
                &kd.lib,
                None,
                &[approved],
                &guard::Counts::default(),
                false,
                READ.wall_ms as i64,
            )
            .unwrap();
            let (paused, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(paused.asking.is_some());
            assert!(kit.devices[0].db.annotations("book").unwrap().is_empty());
            let kd = &kit.devices[0];
            guard::answer(
                kd.db.conn(),
                &kd.lib,
                guard::Answer::Apply,
                READ.wall_ms as i64 + 1,
            )
            .unwrap();
            pass_at(
                &mut kit.devices[0],
                Readings {
                    wall_ms: READ.wall_ms + 2,
                    ..READ
                },
                &Budgets::sy2(),
            );
            assert!(
                kit.devices[0].db.annotations("book").unwrap().is_empty(),
                "the unapproved newer winner must wait"
            );
            pass_at(
                &mut kit.devices[0],
                Readings {
                    wall_ms: READ.wall_ms + 3,
                    ..READ
                },
                &Budgets::sy2(),
            );
            let rows = kit.devices[0].db.annotations("book").unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].note.as_deref(), Some("newer"));
            let counted: i64 = kit.devices[0]
                .db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sync_counted WHERE approved = 0",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(counted > 0, "the newer version is counted normally");
        }

        #[test]
        fn process_kill_between_steps_and_inside_apply_recovers() {
            use crate::sync::device_store::{Keystore, StoreError};
            use crate::sync::files::{self, Read};
            use serde::{Deserialize, Serialize};
            use std::path::PathBuf;

            #[derive(Serialize, Deserialize)]
            struct Fixture {
                library: String,
                device: String,
                files: Vec<(String, Vec<u8>)>,
            }
            struct FileKeys(PathBuf);
            impl Keystore for FileKeys {
                fn load(&self) -> Result<Option<Vec<u8>>, StoreError> {
                    std::fs::read(&self.0)
                        .map(Some)
                        .map_err(|_| StoreError::Unreadable)
                }
                fn save(&self, bytes: &[u8]) -> Result<(), StoreError> {
                    std::fs::write(&self.0, bytes).map_err(|_| StoreError::Unreadable)
                }
            }
            struct DiskFolder(PathBuf);
            impl DiskFolder {
                fn load(&self) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
                    serde_json::from_slice(&std::fs::read(&self.0)?).map_err(std::io::Error::other)
                }
                fn save(&self, map: &BTreeMap<String, Vec<u8>>) -> std::io::Result<()> {
                    std::fs::write(
                        &self.0,
                        serde_json::to_vec(map).map_err(std::io::Error::other)?,
                    )
                }
            }
            impl Folder for DiskFolder {
                type Token = String;
                fn list(
                    &self,
                    dir: &str,
                    _: Option<&str>,
                ) -> std::io::Result<crate::sync::folder::Page<String>> {
                    let prefix = format!("{dir}/");
                    let entries = self
                        .load()?
                        .into_keys()
                        .filter(|path| {
                            path.strip_prefix(&prefix)
                                .is_some_and(|rest| !rest.contains('/'))
                        })
                        .map(|name| crate::sync::folder::Listed {
                            token: name.clone(),
                            name,
                            ours: true,
                        })
                        .collect();
                    Ok(crate::sync::folder::Page {
                        entries,
                        next: None,
                    })
                }
                fn stat(&self, token: &String) -> std::io::Result<Option<u64>> {
                    Ok(self.load()?.get(token).map(|b| b.len() as u64))
                }
                fn read(
                    &self,
                    token: &String,
                    limit: Option<u64>,
                ) -> std::io::Result<crate::sync::folder::Read> {
                    Ok(match self.load()?.remove(token) {
                        Some(bytes) if limit.is_some_and(|n| bytes.len() as u64 > n) => {
                            crate::sync::folder::Read::TooLarge
                        }
                        Some(bytes) => crate::sync::folder::Read::Bytes(bytes),
                        None => crate::sync::folder::Read::Gone,
                    })
                }
                fn write(&mut self, path: &str, bytes: &[u8]) -> std::io::Result<()> {
                    let mut map = self.load()?;
                    map.insert(path.to_string(), bytes.to_vec());
                    self.save(&map)
                }
                fn remove(&mut self, token: &String) -> std::io::Result<()> {
                    let mut map = self.load()?;
                    map.remove(token);
                    self.save(&map)
                }
            }
            if let Ok(dir) = std::env::var("LINEN_B3_KILL_FIXTURE") {
                let root = PathBuf::from(dir);
                let input: Fixture =
                    serde_json::from_slice(&std::fs::read(root.join("input.json")).unwrap())
                        .unwrap();
                let lib = crate::sync::journal::Library {
                    id: Id16::parse(&input.library).unwrap(),
                    device: DeviceId::parse(&input.device).unwrap(),
                };
                let db = std::sync::Mutex::new(
                    crate::store::Store::open(&root.join("library.db")).unwrap(),
                );
                let ks = FileKeys(root.join("keys"));
                let mut store = crate::sync::device_store::DeviceStore::load(&ks).unwrap();
                let state = State::load(db.lock().unwrap().conn(), &lib.id).unwrap();
                let mut folder = DiskFolder(root.join("folder.json"));
                if let Ok(target) = std::env::var("LINEN_B3_KILL_POINT") {
                    HOOK.with(|h| {
                        *h.borrow_mut() = Some(Box::new(move |point, _| {
                            if format!("{point:?}") == target {
                                // A real process death leaves SQLite and the key store as they stand.
                                unsafe {
                                    libc::kill(libc::getpid(), libc::SIGKILL);
                                }
                            }
                            Ok(())
                        }))
                    });
                }
                let mut device = Device {
                    db: Database::Store(&db),
                    root: &root,
                    lib,
                    store: &mut store,
                    ks: &ks,
                    state,
                    name: "Test Mac",
                };
                run(&mut device, &mut folder, READ, &Budgets::sy2(), &|| 0).unwrap();
                let quiet = run(&mut device, &mut folder, READ, &Budgets::sy2(), &|| 0).unwrap();
                assert!(quiet.received.is_empty());
                let rows = db.lock().unwrap().annotations("book").unwrap();
                assert_eq!(rows.len(), 2);
                assert!(rows
                    .iter()
                    .any(|row| row.note.as_deref() == Some("survives")));
                assert!(rows
                    .iter()
                    .any(|row| row.note.as_deref() == Some("local survives")));
                assert!(device.store.library(&lib.id).unwrap().seq > 0);
                return;
            }
            let mut kit = testkit::library(2);
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("survives"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
            let mut local = highlight("book", Some("local survives"), 1_760_000_002_000);
            local.id = "2b3c4d5e-6f7a-4b1c-9d2e-4f5a6b7c8d9e".into();
            kit.devices[0].db.save_annotation(&local).unwrap();
            let kd = &kit.devices[0];
            let peer = kit.devices[1].lib.device;
            let dirs = [
                "libraries".to_string(),
                "trust".to_string(),
                "devices".to_string(),
                "blobs".to_string(),
                format!("changes/{peer}"),
            ];
            let mut files = Vec::new();
            for dir in dirs {
                for entry in kd.folder.list(&dir, None).unwrap().entries {
                    if let Read::Bytes(bytes) = files::read_file(&kd.folder, &entry).unwrap() {
                        files.push((entry.name, bytes));
                    }
                }
            }
            let input = Fixture {
                library: kd.lib.id.to_string(),
                device: kd.lib.device.to_string(),
                files,
            };
            let executable = std::env::current_exe().unwrap();
            for point in [
                "After(1)",
                "After(2)",
                "After(3)",
                "After(4)",
                "After(5)",
                "Locked",
                "BackedUp",
                "Applied",
                "Committed",
                "After(6)",
                "After(9)",
                "After(10)",
            ] {
                let dir = tempfile::tempdir().unwrap();
                kd.db
                    .conn()
                    .backup(
                        rusqlite::MAIN_DB,
                        dir.path().join("library.db"),
                        rusqlite::backup::NO_PROGRESS,
                    )
                    .unwrap();
                std::fs::write(dir.path().join("keys"), kd.ks.load().unwrap().unwrap()).unwrap();
                std::fs::write(
                    dir.path().join("input.json"),
                    serde_json::to_vec(&input).unwrap(),
                )
                .unwrap();
                let initial: BTreeMap<_, _> = input.files.iter().cloned().collect();
                std::fs::write(
                    dir.path().join("folder.json"),
                    serde_json::to_vec(&initial).unwrap(),
                )
                .unwrap();
                let child = |kill: bool| {
                    let mut cmd = std::process::Command::new(&executable);
                    cmd.arg("--exact").arg("sync::pass::tests::run::process_kill_between_steps_and_inside_apply_recovers")
                        .env("LINEN_B3_KILL_FIXTURE", dir.path());
                    if kill {
                        cmd.env("LINEN_B3_KILL_POINT", point);
                    }
                    cmd.output().unwrap()
                };
                let killed = child(true);
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(
                    killed.status.signal(),
                    Some(libc::SIGKILL),
                    "{point}: {}",
                    String::from_utf8_lossy(&killed.stderr)
                );
                let resumed = child(false);
                assert!(
                    resumed.status.success(),
                    "{point}: {} {}",
                    String::from_utf8_lossy(&resumed.stdout),
                    String::from_utf8_lossy(&resumed.stderr)
                );
            }
        }

        fn pass_at(kd: &mut KitDevice, readings: Readings, budgets: &Budgets) -> (Report, State) {
            let state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let mut device = Device {
                db: crate::sync::pass::Database::Test(&kd.db),
                root: kd.root.path(),
                lib: kd.lib,
                store: &mut kd.store,
                ks: &kd.ks,
                state,
                name: "Test Mac",
            };
            let report = run(&mut device, &mut kd.folder, readings, budgets, &|| 0).unwrap();
            (report, device.state)
        }

        #[test]
        fn three_devices_read_each_others_device_files() {
            let mut kit = testkit::library(3);
            let peers: Vec<_> = kit.devices[1..].iter().map(|d| d.lib.device).collect();
            let (report, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert_eq!(report.stopped, None);
            assert_eq!(report.trusted.len(), 3);
            let mut accepted = report.accepted.clone();
            accepted.sort();
            let mut expected = peers.clone();
            expected.sort();
            assert_eq!(accepted, expected);
            for peer in &peers {
                assert!(state.heard.heard(peer).is_some_and(|(n, _)| n > 0));
            }
            // SP20 (1): every trust record is timed from when it was first seen.
            let trust = kit.devices[0]
                .folder
                .list("trust", None)
                .unwrap()
                .entries
                .len();
            assert_eq!(state.membership.first_seen.len(), trust);
            // Saved: a second pass loads it and finds nothing new.
            let (again, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(again.accepted.is_empty());
            assert_eq!(again.trusted.len(), 3);
        }

        #[test]
        fn each_budget_stops_the_pass() {
            let tight = |f: fn(&mut Budgets)| {
                let mut b = Budgets::sy2();
                f(&mut b);
                b
            };
            for (budgets, stop) in [
                (tight(|b| b.names = 1), Stopped::Names),
                (tight(|b| b.devices = 0), Stopped::Devices),
                (tight(|b| b.bytes = 10), Stopped::Bytes),
            ] {
                let mut kit = testkit::library(3);
                let (report, _) = pass(&mut kit.devices[0], &budgets);
                assert_eq!(report.stopped, Some(stop));
            }
            // Time: the injected clock jumps past the budget after the start.
            let mut kit = testkit::library(3);
            let kd = &mut kit.devices[0];
            let calls = Cell::new(0u64);
            let clock = || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    0
                } else {
                    120_000
                }
            };
            let state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let mut device = Device {
                db: crate::sync::pass::Database::Test(&kd.db),
                root: kd.root.path(),
                lib: kd.lib,
                store: &mut kd.store,
                ks: &kd.ks,
                state,
                name: "Test Mac",
            };
            let report = run(&mut device, &mut kd.folder, READ, &Budgets::sy2(), &clock).unwrap();
            assert_eq!(report.stopped, Some(Stopped::Time));
        }

        #[test]
        fn membership_is_read_before_device_files() {
            let mut kit = testkit::library(3);
            // Enough names for libraries/ and trust/, none to spare for devices/.
            let kd = &kit.devices[0];
            let count = |dir| kd.folder.list(dir, None).unwrap().entries.len() as u64;
            let names = count("libraries") + count("trust");
            let mut budgets = Budgets::sy2();
            budgets.names = names;
            let (report, _) = pass(&mut kit.devices[0], &budgets);
            assert_eq!(report.stopped, Some(Stopped::Names));
            assert_eq!(report.trusted.len(), 3, "membership was computed");
            assert!(report.accepted.is_empty(), "no device file was read");
        }

        #[test]
        fn a_crash_before_saving_heard_is_caught_up_next_pass() {
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            pass(&mut kit.devices[0], &Budgets::sy2());
            // The crash: the floor survives in the device store, Heard doesn't.
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let counter = state.heard.heard(&peer).unwrap().0;
            state.heard = Default::default();
            let tx = kd.db.conn().unchecked_transaction().unwrap();
            state.save(&tx, &kd.lib.id).unwrap();
            tx.commit().unwrap();
            let (report, state) = pass(kd, &Budgets::sy2());
            assert!(report.accepted.is_empty(), "the file is stale now");
            assert_eq!(
                state.heard.heard(&peer),
                Some((counter, 0)),
                "counter, not time"
            );
        }

        fn file_bytes(kd: &KitDevice, dir: &str) -> Vec<u64> {
            kd.folder
                .list(dir, None)
                .unwrap()
                .entries
                .iter()
                .map(
                    |e| match crate::sync::files::read_file(&kd.folder, e).unwrap() {
                        crate::sync::files::Read::Bytes(b) => b.len() as u64,
                        _ => panic!("unreadable {}", e.name),
                    },
                )
                .collect()
        }

        fn save_raw(kd: &KitDevice, state: &State) {
            let tx = kd.db.conn().unchecked_transaction().unwrap();
            state.save(&tx, &kd.lib.id).unwrap();
            tx.commit().unwrap();
        }

        /// Gives `peer` a device file at counter 2 whose lists spill into
        /// overflow parts, one per list named.
        fn write_with_parts(
            peer: &mut KitDevice,
            lists: &[&str],
        ) -> crate::sync::device_file::Written {
            let lib = peer.store.library(&peer.lib.id).unwrap();
            let writer = lib.writer_id().unwrap();
            let head = lib
                .rest
                .get("head")
                .and_then(|v| v.as_str())
                .and_then(Hash32::parse);
            let frontier: Vec<serde_json::Value> = (0..4000)
                .map(|i| serde_json::json!({ "d": format!("{i:032x}"), "s": i, "h": "ab".repeat(32), "sig": "c".repeat(86) }))
                .collect();
            let mut fields = crate::sync::device_file::Fields {
                head,
                ..Default::default()
            };
            for list in lists {
                fields.lists.insert((*list).into(), frontier.clone());
            }
            let w = crate::sync::device_file::write(&peer.key, &peer.lib.id, &writer, 2, &fields)
                .unwrap();
            assert!(!w.parts.is_empty());
            for (path, bytes) in &w.parts {
                crate::sync::files::write_file(&mut peer.folder, path, bytes).unwrap();
            }
            crate::sync::files::write_file(&mut peer.folder, &w.path, &w.bytes).unwrap();
            w
        }

        #[test]
        fn a_device_file_with_overflow_parts_is_accepted() {
            // SP16: the parts are in devices/<peer>/, not in devices/ itself.
            let mut kit = testkit::library(2);
            let peer = &mut kit.devices[1];
            let w = write_with_parts(peer, &["frontier"]);
            let id = peer.lib.device;
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert_eq!(
                report.accepted,
                vec![id],
                "set aside: {:?}",
                report.set_aside
            );
            let parts: u64 = w.parts.iter().map(|(_, b)| b.len() as u64).sum();
            assert!(report.bytes_read > parts, "the parts' bytes are counted");
        }

        #[test]
        fn overflow_parts_are_read_within_the_byte_budget() {
            // PS6: a file naming several parts stops the pass after the first
            // part past the budget, before the rest are read.
            let mut kit = testkit::library(2);
            let w = write_with_parts(&mut kit.devices[1], &["frontier", "repairs"]);
            assert!(w.parts.len() >= 2);
            let kd = &kit.devices[0];
            let mut budgets = Budgets::sy2();
            budgets.bytes = file_bytes(kd, "trust").iter().sum::<u64>() + w.bytes.len() as u64;
            let (report, _) = pass(&mut kit.devices[0], &budgets);
            assert_eq!(report.stopped, Some(Stopped::Bytes));
            assert!(report.accepted.is_empty());
            let first = w.parts.iter().map(|(_, b)| b.len() as u64).max().unwrap();
            assert!(
                report.bytes_read <= budgets.bytes + first,
                "one part at most"
            );
        }

        #[test]
        fn a_quarantined_peers_device_file_is_not_accepted() {
            // SP30: its head stays where it was.
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            state.membership.quarantined.insert(peer, None);
            save_raw(kd, &state);
            let (report, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(!report.accepted.contains(&peer), "{report:?}");
            assert!(!state.membership.heads.contains_key(&peer));
        }

        #[test]
        fn a_code_enrollment_counts_once_a_trusted_peers_head_includes_it() {
            // SP20 (2): device 1's file names a head with C's code enrollment.
            use crate::sync::crypto::{CodeKeys, Keypair};
            let mut kit = testkit::library(2);
            let lib = kit.devices[0].lib.id;
            let genesis = kit.devices[0]
                .store
                .library(&lib)
                .unwrap()
                .rest
                .get("genesis")
                .and_then(|v| v.as_str())
                .and_then(Hash32::parse)
                .unwrap();
            let c = Keypair::from_seed(&[77; 32]);
            let code = CodeKeys {
                signing: Keypair::from_seed(&[99; 32]),
                escrow: [0; 32],
            };
            let (bytes, enroll) = crate::sync::recovery::enroll_by_code(
                &lib,
                &genesis,
                &code,
                &c,
                "C",
                crate::sync::clock::Hlc(1_790_000_000_000, 2),
            );
            crate::sync::files::write_file(
                &mut kit.devices[1].folder,
                &crate::sync::trust::trust_path(&enroll),
                &bytes,
            )
            .unwrap();
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(!report.trusted.contains(&c.device()), "waits for a confirm");
            let peer = &mut kit.devices[1];
            let writer = peer.store.library(&lib).unwrap().writer_id().unwrap();
            let fields = crate::sync::device_file::Fields {
                head: Some(enroll),
                ..Default::default()
            };
            let w = crate::sync::device_file::write(&peer.key, &lib, &writer, 2, &fields).unwrap();
            crate::sync::files::write_file(&mut peer.folder, &w.path, &w.bytes).unwrap();
            pass(&mut kit.devices[0], &Budgets::sy2());
            let (report, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(report.trusted.contains(&c.device()), "{report:?}");
            assert!(state.membership.confirmed.contains(&enroll));
        }

        #[test]
        fn first_seen_times_are_saved_when_storage_is_stale() {
            // PS5, SP21: the genesis this device accepted is missing for now.
            let mut kit = testkit::library(3);
            pass(&mut kit.devices[0], &Budgets::sy2());
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let genesis = kd
                .store
                .library(&kd.lib.id)
                .unwrap()
                .rest
                .get("genesis")
                .and_then(|v| v.as_str())
                .and_then(Hash32::parse)
                .unwrap();
            state.membership.first_seen.clear();
            save_raw(kd, &state);
            let path = crate::sync::trust::trust_path(&genesis);
            let listed = kd.folder.list("trust", None).unwrap().entries;
            let token = listed.into_iter().find(|e| e.name == path).unwrap().token;
            kd.folder.remove(&token).unwrap();
            let state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let mut device = Device {
                db: crate::sync::pass::Database::Test(&kd.db),
                root: kd.root.path(),
                lib: kd.lib,
                store: &mut kd.store,
                ks: &kd.ks,
                state,
                name: "Test Mac",
            };
            assert!(run(&mut device, &mut kd.folder, READ, &Budgets::sy2(), &|| 0).is_err());
            let saved = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            assert_eq!(saved.membership.first_seen.len(), 2);
        }

        use crate::sync::apply::tests::{highlight, note_of};

        #[test]
        fn a_peers_note_and_deletion_are_received_in_order() {
            // SP37 (4), SP18: the change files follow the accepted device file.
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("Call me"), 1_760_000_001_000))
                .unwrap();
            assert_eq!(kit.devices[1].publish_pending(), Some(1));
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert_eq!(report.received, vec![(peer, 1)], "{report:?}");
            assert!(report.behind.is_empty());
            assert_eq!(
                note_of(&kit.devices[0].db, "book"),
                Some(Some("Call me".into()))
            );
            // Nothing new: nothing is read again.
            let (again, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(again.received.is_empty());
            let id = kit.devices[1].db.annotations("book").unwrap()[0].id.clone();
            kit.devices[1].db.delete_annotation(&id).unwrap();
            assert_eq!(kit.devices[1].publish_pending(), Some(2));
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert_eq!(report.received, vec![(peer, 2)], "{report:?}");
            assert_eq!(note_of(&kit.devices[0].db, "book"), None);
        }

        #[test]
        fn applied_remote_deletion_keeps_its_vouched_age_across_restart() {
            use crate::sync::record::Entry;
            let mut kit = testkit::library(2);
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("remote"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
            pass(&mut kit.devices[0], &Budgets::sy2());
            let id = kit.devices[1].db.annotations("book").unwrap()[0].id.clone();
            kit.devices[1].db.delete_annotation(&id).unwrap();
            kit.devices[1].publish_pending();
            let (_, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            let kd = &kit.devices[0];
            let (writer, seq, hash): (String, i64, String) = kd.db.conn().query_row(
                "SELECT device, seq, hash FROM sync_deleted WHERE library = ?1 AND seq IS NOT NULL LIMIT 1",
                [kd.lib.id.to_string()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).unwrap();
            let entry = Entry {
                device: DeviceId::parse(&writer).unwrap(),
                seq: seq as u64,
                hash: Hash32::parse(&hash).unwrap(),
            };
            assert_eq!(state.ages.own_age(&entry, state.vouched.now()), Some(0));
            let loaded = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            assert_eq!(loaded.ages.own_age(&entry, loaded.vouched.now()), Some(0));
        }

        #[test]
        fn quarantined_writers_future_version_cannot_apply_when_clock_catches_up() {
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("future"), 1_760_000_001_000))
                .unwrap();
            let sender = &kit.devices[1];
            let mut batch = crate::sync::apply::tests::publish_next(sender.db.conn(), &sender.lib)
                .unwrap()
                .unwrap();
            for version in &mut batch.versions {
                version["clock"] = serde_json::json!([READ.wall_ms + 30 * 60 * 60 * 1000, 0]);
            }
            let kd = &mut kit.devices[0];
            crate::sync::apply::receive(kd.db.conn(), &kd.lib, &batch, READ.wall_ms as i64)
                .unwrap();
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            state.membership.quarantined.insert(peer, None);
            save_raw(kd, &state);
            let future = Readings {
                wall_ms: READ.wall_ms + 2 * 24 * 60 * 60 * 1000,
                ..READ
            };
            pass_at(kd, future, &Budgets::sy2());
            assert!(kd.db.annotations("book").unwrap().is_empty());
            let held: i64 = kd
                .db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sync_versions WHERE device = ?1 AND applied = -5",
                    [peer.to_string()],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(held > 0, "the future version is held as a late change");
            pass_at(kd, future, &Budgets::sy2());
            assert!(kd.db.annotations("book").unwrap().is_empty());
        }

        #[test]
        fn two_devices_exchange_a_note_and_a_deletion_through_run() {
            // P2's first Done-when, #213. Every move is a whole `run`: a device
            // publishes in steps (9)-(10), the other receives in step (4) and applies
            // in the same call, as `chain::receive_run` does until step (6) takes
            // that over under the lock (B3, #198): so no lock, no SY26 guard and no
            // SY27 backup stand in this exchange. The kit's `publish_pending` isn't
            // used.
            let mut kit = testkit::library(2);
            let ids: Vec<_> = kit.devices.iter().map(|d| d.lib.device).collect();
            for (from, to) in [(0, 1), (1, 0)] {
                let text = format!("note from {from}");
                // A second note, not the first again: the first was deleted, and a
                // version older than its deletion would lose to it (SP11).
                let row = crate::store::AnnotationRow {
                    id: format!("2b3c4d5e-6f7a-4b1c-9d2e-4f5a6b7c8d9{from}"),
                    cfi_range: format!("epubcfi(/6/4!/4/{},/1:0,/1:4)", 2 + from),
                    ..highlight("book", Some(&text), 1_760_000_001_000)
                };
                kit.devices[from].db.save_annotation(&row).unwrap();
                let (sent, _) = pass(&mut kit.devices[from], &Budgets::sy2());
                assert!(!sent.published.changes.is_empty(), "{sent:?}");
                assert_eq!(note_of(&kit.devices[to].db, "book"), None);
                let (got, _) = pass(&mut kit.devices[to], &Budgets::sy2());
                assert_eq!(got.received.len(), 1, "{got:?}");
                assert_eq!(got.received[0].0, ids[from]);
                assert_eq!(note_of(&kit.devices[to].db, "book"), Some(Some(text)));
                // The receiver deletes it; the sender, in its next pass, loses it too.
                let id = kit.devices[to].db.annotations("book").unwrap()[0]
                    .id
                    .clone();
                kit.devices[to].db.delete_annotation(&id).unwrap();
                let (sent, _) = pass(&mut kit.devices[to], &Budgets::sy2());
                assert!(!sent.published.changes.is_empty(), "{sent:?}");
                assert!(note_of(&kit.devices[from].db, "book").is_some(), "not yet");
                let (got, _) = pass(&mut kit.devices[from], &Budgets::sy2());
                assert_eq!(got.received.len(), 1, "{got:?}");
                assert_eq!(note_of(&kit.devices[from].db, "book"), None);
                assert_eq!(note_of(&kit.devices[to].db, "book"), None);
                // Quiet again: nothing is sent and nothing is received.
                for kd in &mut kit.devices {
                    let (quiet, _) = pass(kd, &Budgets::sy2());
                    assert!(quiet.received.is_empty() && quiet.published.changes.is_empty());
                }
            }
        }

        #[test]
        fn a_restart_between_whole_passes_keeps_a_deletions_age_and_a_witness_timeout() {
            // P2's last Done-when, #213, SY17, SP32, SP35, PS5. The pass doesn't mark a
            // deletion's age itself yet (that is step (6)'s apply), so the age is
            // marked in the saved state between two passes; what is tested is that
            // whole passes over restarts keep it and the witness timeout where they
            // were. The first pass hears the peer's device file at vouched time 0.
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            let (_, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert_eq!(state.heard.heard(&peer).map(|h| h.1), Some(0));
            let gone = crate::sync::record::Entry {
                device: peer,
                seq: 1,
                hash: Hash32([3; 32]),
            };
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            state.ages.saw(gone, state.vouched.now());
            super::save(&mut kd.db, &kd.lib.id, &state);
            let wall = READ.wall_ms;
            let at = |mono_ms, wall_ms, clock_ahead, same_boot| Readings {
                mono_ms,
                wall_ms,
                clock_ahead,
                same_boot,
            };
            // Each pass: its readings, whether the peer writes a new device file first,
            // the deletion's age after it and the time since the peer was last heard.
            let restarts = [
                // The same boot, a minute later: the peer was last heard at 0.
                (
                    at(61_000, wall + 60_000, false, true),
                    false,
                    60_000,
                    60_000,
                ),
                // The peer writes again, and is heard at the minute.
                (at(61_000, wall + 60_000, false, true), true, 60_000, 0),
                // After a reboot, the wall clock bridges the hour the device was off.
                (
                    at(5, wall + 3_660_000, false, false),
                    false,
                    3_660_000,
                    3_600_000,
                ),
                // After a reboot with the clock marked ahead (SY10), nothing is bridged:
                // both stay where they were, neither is reset.
                (
                    at(5, wall + 9_999_999_999, true, false),
                    false,
                    3_660_000,
                    3_600_000,
                ),
            ];
            for (readings, writes, age, timeout) in restarts {
                if writes {
                    kit.devices[1].publish_device_file();
                }
                let (_, state) = pass_at(&mut kit.devices[0], readings, &Budgets::sy2());
                assert_eq!(state.ages.own_age(&gone, state.vouched.now()), Some(age));
                let heard_at = state.heard.heard(&peer).unwrap().1;
                assert_eq!(
                    state.vouched.now() - heard_at,
                    timeout,
                    "the witness timeout"
                );
                // And what was saved says the same to a process that starts afresh.
                let kd = &kit.devices[0];
                let loaded = State::load(kd.db.conn(), &kd.lib.id).unwrap();
                assert_eq!(loaded.vouched.now(), state.vouched.now());
                assert_eq!(loaded.ages.own_age(&gone, loaded.vouched.now()), Some(age));
                assert_eq!(loaded.heard.heard(&peer).map(|h| h.1), Some(heard_at));
            }
        }

        #[test]
        fn a_change_file_not_in_storage_yet_leaves_the_peer_behind() {
            // SP14, SP18: the device file names change 1; its file hasn't synced.
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("Call me"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
            let kd = &mut kit.devices[1];
            let path = crate::sync::chain::change_path(&peer, 1);
            let entry = kd
                .folder
                .list(&format!("changes/{peer}"), None)
                .unwrap()
                .entries
                .into_iter()
                .find(|e| e.name == path)
                .unwrap();
            let bytes = match crate::sync::files::read_file(&kd.folder, &entry).unwrap() {
                crate::sync::files::Read::Bytes(b) => b,
                _ => panic!("unreadable"),
            };
            kd.folder.remove(&entry.token).unwrap();
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(report.received.is_empty());
            assert_eq!(report.behind, vec![peer]);
            assert_eq!(note_of(&kit.devices[0].db, "book"), None);
            // It syncs later: the next pass takes it, with no new device file.
            crate::sync::files::write_file(&mut kit.devices[1].folder, &path, &bytes).unwrap();
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert_eq!(report.received, vec![(peer, 1)], "{report:?}");
            assert!(report.behind.is_empty());
            assert_eq!(
                note_of(&kit.devices[0].db, "book"),
                Some(Some("Call me".into()))
            );
        }

        #[test]
        fn step_four_stops_at_the_name_budget() {
            // PS6: the listing of a peer's changes counts against the budget.
            let mut kit = testkit::library(2);
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("Call me"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
            let kd = &kit.devices[0];
            let count = |dir| kd.folder.list(dir, None).unwrap().entries.len() as u64;
            let mut budgets = Budgets::sy2();
            budgets.names = count("libraries") + count("trust") + count("devices");
            let (report, _) = pass(&mut kit.devices[0], &budgets);
            assert_eq!(report.stopped, Some(Stopped::Names));
            assert!(report.received.is_empty());
            assert_eq!(note_of(&kit.devices[0].db, "book"), None);
            // The peer is still behind, however the pass ended.
            assert_eq!(report.behind, vec![kit.devices[1].lib.device]);
        }

        fn peer_with_note(kit: &mut testkit::Kit) {
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("Call me"), 1_760_000_001_000))
                .unwrap();
            kit.devices[1].publish_pending();
        }

        #[test]
        fn a_budget_that_runs_out_on_a_blob_still_receives_the_change() {
            // PS6, SY28: the change is received, and what was read with it; a
            // body not fetched waits for step 5. The next pass has less to do.
            let mut kit = testkit::library(2);
            peer_with_note(&mut kit);
            let peer = kit.devices[1].lib.device;
            let kd = &kit.devices[0];
            let mut budgets = Budgets::sy2();
            budgets.bytes = file_bytes(kd, "trust").iter().sum::<u64>()
                + file_bytes(kd, &format!("changes/{peer}"))
                    .iter()
                    .sum::<u64>()
                + file_bytes(kd, "devices")[..].iter().min().copied().unwrap();
            let (report, _) = pass(&mut kit.devices[0], &budgets);
            assert_eq!(report.stopped, Some(Stopped::Bytes), "{report:?}");
            assert_eq!(report.received, vec![(peer, 1)]);
            assert!(report.behind.is_empty());
        }

        #[test]
        fn a_run_reaches_the_floors_checkpoint_past_the_run_cap() {
            // SP18: with a checkpoint at 2 and the floor at 3, a run capped at one
            // change would never reach it and would wait for ever.
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            peer_with_note(&mut kit);
            let id = kit.devices[1].db.annotations("book").unwrap()[0].id.clone();
            kit.devices[1].db.delete_annotation(&id).unwrap();
            kit.devices[1].publish_pending();
            // The first pass accepts the device file (own = 2) but reads no change.
            let kd = &kit.devices[0];
            let count = |dir| kd.folder.list(dir, None).unwrap().entries.len() as u64;
            let mut stop = Budgets::sy2();
            stop.names = count("libraries") + count("trust") + count("devices");
            let (report, _) = pass(&mut kit.devices[0], &stop);
            assert_eq!(report.stopped, Some(Stopped::Names));
            kit.devices[1]
                .db
                .save_annotation(&highlight("book", Some("again"), 1_760_000_009_000))
                .unwrap();
            assert_eq!(kit.devices[1].publish_pending(), Some(3));
            let mut capped = Budgets::sy2();
            capped.run_bytes = 1;
            let (report, _) = pass(&mut kit.devices[0], &capped);
            assert_eq!(report.received, vec![(peer, 2)], "{report:?}");
            assert_eq!(report.behind, vec![peer]);
        }

        #[test]
        fn behind_is_reported_when_an_earlier_step_runs_out_of_budget() {
            // The floor is ahead from an earlier pass; this one stops in step (3).
            let mut kit = testkit::library(2);
            peer_with_note(&mut kit);
            let peer = kit.devices[1].lib.device;
            let kd = &kit.devices[0];
            let count = |dir| kd.folder.list(dir, None).unwrap().entries.len() as u64;
            let mut first = Budgets::sy2();
            first.names = count("libraries") + count("trust") + count("devices");
            pass(&mut kit.devices[0], &first);
            let mut second = Budgets::sy2();
            second.devices = 0;
            let (report, _) = pass(&mut kit.devices[0], &second);
            assert_eq!(report.stopped, Some(Stopped::Devices));
            assert_eq!(report.behind, vec![peer]);
        }

        #[test]
        fn a_peer_this_device_stopped_receiving_from_is_not_fetched() {
            // SY28: the pass spends nothing on it, and it stays behind.
            let mut kit = testkit::library(2);
            peer_with_note(&mut kit);
            let peer = kit.devices[1].lib.device;
            let kd = &kit.devices[0];
            crate::sync::apply::stop(kd.db.conn(), &kd.lib, peer, "test", 1).unwrap();
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(report.received.is_empty());
            assert_eq!(report.behind, vec![peer]);
            let trust: u64 = file_bytes(&kit.devices[0], "trust").iter().sum();
            // The peer's device file, and this device's own, which step (10) reads to
            // see whether it says anything new.
            let device_files: u64 = file_bytes(&kit.devices[0], "devices").iter().sum();
            assert!(
                report.bytes_read <= trust + device_files,
                "no change or blob was read"
            );
        }

        #[test]
        fn a_blob_bigger_than_its_types_limit_is_set_aside_unread() {
            // SY28: the version declares a small place; storage holds 9 KB (the
            // limit is 8 KB), under the generic 4 MB blob limit.
            let mut kit = testkit::library(2);
            kit.devices[1]
                .db
                .save_position("book", "epubcfi(/6/4!/4/2/1:0)", 0.3, Some("One"))
                .unwrap();
            kit.devices[1].publish_pending();
            let kd = &mut kit.devices[1];
            let blob = kd
                .folder
                .list("blobs", None)
                .unwrap()
                .entries
                .into_iter()
                .next()
                .unwrap();
            crate::sync::files::write_file(&mut kd.folder, &blob.name, &vec![b'x'; 9 << 10])
                .unwrap();
            let (report, _) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(
                report
                    .set_aside
                    .iter()
                    .any(|(path, why)| *path == blob.name && why == "over its limit"),
                "{report:?}"
            );
        }

        #[test]
        fn a_body_past_its_types_limit_is_not_fetched() {
            use serde_json::json;
            let over = |key: &str, size: u64| {
                body_over_limit(
                    &json!({ "key": key, "body": { "hash": "ab".repeat(32), "size": size } }),
                )
            };
            assert!(over("setting:fontPx", 64 * 1024 + 1));
            assert!(!over("setting:fontPx", 64 * 1024));
            assert!(!over("note:1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d", 4 << 20));
            assert!(over(
                "note:1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d",
                (4 << 20) + 1
            ));
            assert!(!body_over_limit(&json!({ "key": "setting:fontPx" })));
        }

        #[test]
        fn first_seen_times_are_pruned_even_when_a_budget_stops_the_pass() {
            // PS5, SY2: the listing is whole before any record is read.
            let mut kit = testkit::library(3);
            pass(&mut kit.devices[0], &Budgets::sy2());
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            state.membership.first_seen.insert(Hash32([9; 32]), 5);
            save_raw(kd, &state);
            let mut budgets = Budgets::sy2();
            budgets.bytes = 1;
            let (report, state) = pass(kd, &budgets);
            assert_eq!(report.stopped, Some(Stopped::Bytes));
            assert!(!state.membership.first_seen.contains_key(&Hash32([9; 32])));
            let saved = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            assert!(!saved.membership.first_seen.contains_key(&Hash32([9; 32])));
        }

        #[test]
        fn a_head_naming_a_disconnected_enrollment_confirms_nothing() {
            // SP20 (2): only an enrollment membership is waiting on is confirmed.
            use crate::sync::crypto::{CodeKeys, Keypair};
            let mut kit = testkit::library(2);
            let lib = kit.devices[0].lib.id;
            let code = CodeKeys {
                signing: Keypair::from_seed(&[99; 32]),
                escrow: [0; 32],
            };
            let (bytes, bogus) = crate::sync::recovery::enroll_by_code(
                &lib,
                &Hash32([5; 32]),
                &code,
                &Keypair::from_seed(&[77; 32]),
                "C",
                crate::sync::clock::Hlc(1_790_000_000_000, 2),
            );
            crate::sync::files::write_file(
                &mut kit.devices[1].folder,
                &crate::sync::trust::trust_path(&bogus),
                &bytes,
            )
            .unwrap();
            let peer = &mut kit.devices[1];
            let writer = peer.store.library(&lib).unwrap().writer_id().unwrap();
            let fields = crate::sync::device_file::Fields {
                head: Some(bogus),
                ..Default::default()
            };
            let w = crate::sync::device_file::write(&peer.key, &lib, &writer, 2, &fields).unwrap();
            crate::sync::files::write_file(&mut peer.folder, &w.path, &w.bytes).unwrap();
            pass(&mut kit.devices[0], &Budgets::sy2());
            let (_, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            assert!(state.membership.confirmed.is_empty());
        }

        #[test]
        fn first_seen_times_are_kept_only_for_records_in_trust() {
            // PS5, SY2: records added and removed again don't grow the state.
            let mut kit = testkit::library(2);
            pass(&mut kit.devices[0], &Budgets::sy2());
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            let kept = state.membership.first_seen.clone();
            state.membership.first_seen.insert(Hash32([9; 32]), 5);
            save_raw(kd, &state);
            let (_, state) = pass(kd, &Budgets::sy2());
            assert_eq!(state.membership.first_seen, kept);
        }

        #[test]
        fn a_read_past_the_byte_budget_is_not_accepted() {
            // PS6: the budget is checked after each device file's read, not only
            // before the next peer's.
            let mut kit = testkit::library(3);
            let kd = &kit.devices[0];
            let mut budgets = Budgets::sy2();
            budgets.bytes = file_bytes(kd, "trust").iter().sum::<u64>();
            let (report, _) = pass(&mut kit.devices[0], &budgets);
            assert_eq!(report.stopped, Some(Stopped::Bytes));
            assert!(report.accepted.is_empty());
        }

        #[test]
        fn first_seen_times_are_saved_when_the_pass_stops_in_membership() {
            // PS5, SP20 (1): a record opened before the budget ran out keeps the
            // time it was first seen.
            let mut kit = testkit::library(3);
            let kd = &kit.devices[0];
            let sizes = file_bytes(kd, "trust");
            assert!(sizes.len() >= 2);
            let mut budgets = Budgets::sy2();
            budgets.bytes = sizes[0];
            let (report, _) = pass(&mut kit.devices[0], &budgets);
            assert_eq!(report.stopped, Some(Stopped::Bytes));
            let kd = &kit.devices[0];
            let saved = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            assert_eq!(saved.membership.first_seen.len(), 1);
        }

        #[test]
        fn a_crash_before_saving_a_peers_head_takes_it_again() {
            // PS5: the floor was saved with the accepted file, the head wasn't.
            let mut kit = testkit::library(2);
            let peer = kit.devices[1].lib.device;
            let (_, state) = pass(&mut kit.devices[0], &Budgets::sy2());
            let head = state.membership.heads[&peer];
            let kd = &mut kit.devices[0];
            let mut state = State::load(kd.db.conn(), &kd.lib.id).unwrap();
            state.membership.heads.remove(&peer);
            save_raw(kd, &state);
            let (report, state) = pass(kd, &Budgets::sy2());
            assert!(report.accepted.is_empty(), "the file is stale now");
            assert_eq!(state.membership.heads.get(&peer), Some(&head));
        }
    }
}
