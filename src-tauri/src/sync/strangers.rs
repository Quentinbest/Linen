//! SP37 (3), SY34, SY2: the identities membership doesn't hold. Before a device is
//! enrolled nothing of it is believed or kept: Linen reads only its device file (at
//! most 256 KB) and its `enroll/` request (at most 16 KB), and looks at no more than
//! 32 such identities a pass, so nothing from it accumulates. What a pass saw of them
//! goes in the report and nowhere else: no membership input, no floor, no mark and no
//! saved state is touched (`device_file::open` and `enrollment::open_request` only
//! check a file; `device_file::accept`, which writes a floor, is never called). Their
//! changes, views and blobs are never fetched. Enrolling, answering and approving a
//! request are not here: they are SP24's, and the reader's.
//!
//! Which identities: the names `devices/‹id›.json` and `enroll/‹id›.json` in the
//! listings that no enrolled, removed or rotated device of membership carries. An
//! enrollment record that still waits for its quota or its confirmation (SP20) is
//! not held either: its device is looked at like any other, and nothing of it is
//! applied. Which 32, when more are listed (PROVISIONAL, decisions.md, “Step (3)'s
//! unknown identities and removed devices' tails”): those with a request first, then
//! by ID; the rest are counted in `Report::strangers_unread`.

use super::device_file;
use super::enrollment;
use super::files::{self, Kind};
use super::folder::{Folder, Listed};
use super::ids::{DeviceId, Id16};
use super::membership::Membership;
use super::pass::{self, Error, Meter, Report};
use std::collections::{BTreeMap, BTreeSet};

/// SY34, SP37 (3): at most this many identities a pass.
pub const MAX_STRANGERS: usize = 32;

/// What one pass read of an identity membership doesn't hold. Nothing here is
/// believed: the files were signed by the key whose hash is `device`, which says only
/// that one holder of that key wrote them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stranger {
    pub device: DeviceId,
    /// The key the identity's ID is the hash of.
    pub key: [u8; 32],
    /// What it calls itself: its request's name, else its device file's.
    pub name: String,
    /// A request in `enroll/` that checked out (SP24, step 1): “a device asks to
    /// join”.
    pub request: bool,
    /// The counter of its device file, when one checked out.
    pub device_file: Option<u64>,
}

/// The ID a name `‹dir›/‹id›.json` carries, of a name that is exactly that.
fn id_of(name: &str, kind: Kind) -> Option<DeviceId> {
    let id = Id16::parse(name.split_once('/')?.1.strip_suffix(".json")?)?;
    (files::layout(name)?.kind == kind).then_some(id)
}

/// SP37 (3): reads up to 32 unknown identities' device files and requests (a request
/// first, then the device file), within the pass's budgets. A budget that runs out
/// sets `report.stopped` and ends the reading; what was read stays in the report.
pub(super) fn read<F: Folder>(
    lib: &Id16,
    folder: &F,
    membership: &Membership,
    devices: &[Listed<F::Token>],
    meter: &Meter<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    let Some(requests) = pass::list_all(folder, "enroll", meter, report)? else {
        return Ok(());
    };
    let held = |d: &DeviceId| membership.state.members.contains_key(d);
    let mut files: BTreeMap<DeviceId, &Listed<F::Token>> = BTreeMap::new();
    for e in devices {
        if let Some(id) = id_of(&e.name, Kind::Device).filter(|d| !held(d)) {
            files.insert(id, e);
        }
    }
    let mut asked: BTreeMap<DeviceId, &Listed<F::Token>> = BTreeMap::new();
    for e in &requests {
        if let Some(id) = id_of(&e.name, Kind::Enrollment).filter(|d| !held(d)) {
            asked.insert(id, e);
        }
    }
    // SY34: a request first, then the rest by ID.
    let mut order: Vec<DeviceId> = asked.keys().copied().collect();
    let with_request: BTreeSet<DeviceId> = order.iter().copied().collect();
    order.extend(files.keys().filter(|d| !with_request.contains(d)));
    report.strangers_unread = order.len().saturating_sub(MAX_STRANGERS) as u64;
    order.truncate(MAX_STRANGERS);
    for id in order {
        let mut seen = Stranger {
            device: id,
            key: [0; 32],
            name: String::new(),
            request: false,
            device_file: None,
        };
        if let Some(entry) = asked.get(&id) {
            let read = pass::read_bytes(folder, entry, report)?;
            if let Some(stop) = meter.check(report) {
                report.stopped = Some(stop);
                return Ok(());
            }
            if let Some(bytes) = read {
                match enrollment::open_request(&bytes, lib) {
                    // SP24: the name in the path is the applicant the request names.
                    Ok(r) if r.applicant == id => {
                        seen.request = true;
                        seen.key = r.key;
                        seen.name = r.name;
                    }
                    Ok(_) => report
                        .set_aside
                        .push((entry.name.clone(), "names another device".into())),
                    Err(e) => report.set_aside.push((entry.name.clone(), format!("{e}"))),
                }
            }
        }
        if let Some(entry) = files.get(&id) {
            let read = pass::read_bytes(folder, entry, report)?;
            if let Some(stop) = meter.check(report) {
                report.stopped = Some(stop);
                return Ok(());
            }
            if let Some(bytes) = read {
                // A valid request's key is the one the file is held to; without one,
                // the key the file names, which `open` holds to the ID.
                let key = if seen.request {
                    Some(seen.key)
                } else {
                    device_file::named_key(&bytes, lib)
                };
                match key.map(|k| device_file::open(&bytes, lib, &id, &k)) {
                    Some(Ok(file)) => {
                        seen.key = file.key;
                        if !seen.request {
                            seen.name = file.fields.name;
                        }
                        seen.device_file = Some(file.counter);
                    }
                    Some(Err(e)) => report.set_aside.push((entry.name.clone(), format!("{e}"))),
                    None => report
                        .set_aside
                        .push((entry.name.clone(), "names no key".into())),
                }
            }
        }
        if seen.request || seen.device_file.is_some() {
            report.strangers.push(seen);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::crypto::Keypair;
    use crate::sync::device_file::Fields;
    use crate::sync::ids::Hash32;
    use crate::sync::pass::{Budgets, Stopped};
    use crate::sync::testkit::{self, Kit, Watched, READ};
    use std::cell::Cell;
    use std::rc::Rc;

    const WRITER: Id16 = Id16([0xaa; 16]);

    /// A device nobody enrolled, with the files it writes into the folder.
    struct Outsider {
        id: DeviceId,
        key: Keypair,
        request: Vec<u8>,
        file: Vec<u8>,
    }

    fn outsider(kit: &Kit, name: &str) -> Outsider {
        let lib = kit.devices[0].lib.id;
        let (applicant, request) = enrollment::request(&lib, &WRITER, name).unwrap();
        let fields = Fields {
            name: name.into(),
            ..Fields::default()
        };
        let file = device_file::write(&applicant.key, &lib, &WRITER, 1, &fields).unwrap();
        Outsider {
            id: applicant.key.device(),
            key: applicant.key,
            request,
            file: file.bytes,
        }
    }

    /// Writes raw bytes, as a stranger can: no check of ours stands in the way.
    fn put(kit: &mut Kit, path: &str, bytes: &[u8]) {
        kit.devices[1].folder.write(path, bytes).unwrap();
    }

    fn reads(kit: &Kit, path: &str) -> usize {
        kit.folder
            .read_count(&kit.devices[0].lib.device.to_string(), path)
    }

    fn requests(o: &Outsider) -> String {
        enrollment::request_path(&o.id)
    }

    /// What the first device saves, to show a pass changed none of it.
    fn saved(kit: &Kit) -> (crate::sync::device_store::DeviceStore, serde_json::Value) {
        let kd = &kit.devices[0];
        let s = crate::sync::pass::State::load(kd.db.conn(), &kd.lib.id).unwrap();
        let state = serde_json::json!([
            s.membership,
            s.heard,
            s.ledger,
            s.objects,
            s.views,
            s.sigs,
            s.weeks,
            s.marks,
            s.ages
        ]);
        (kd.store.clone(), state)
    }

    #[test]
    fn a_request_and_a_device_file_are_read_reported_and_believed_by_nobody() {
        // SP37 (3), SY34: nothing but the two files is read, and nothing is kept.
        let mut kit = testkit::library(3);
        kit.devices[0].pass();
        let before = saved(&kit);
        let o = outsider(&kit, "Quentin's iPad");
        put(&mut kit, &requests(&o), &o.request);
        put(&mut kit, &device_file::device_path(&o.id), &o.file);
        // What else a stranger can write, which no pass reads.
        let changes = crate::sync::chain::change_path(&o.id, 1);
        let overflow = device_file::overflow_path(&o.id, &Hash32([1; 32]));
        let answer = enrollment::answer_path(&o.id, &kit.devices[1].lib.device);
        for path in [
            &changes,
            &overflow,
            &answer,
            &format!("blobs/{}", "ab".repeat(32)),
        ] {
            put(&mut kit, path, b"{}");
        }
        let report = kit.devices[0].pass();
        assert_eq!(report.stopped, None, "{report:?}");
        let key = o.key.public();
        assert_eq!(
            report.strangers,
            vec![Stranger {
                device: o.id,
                key,
                name: "Quentin's iPad".into(),
                request: true,
                device_file: Some(1)
            }]
        );
        assert_eq!((report.strangers_unread, report.set_aside.len()), (0, 0));
        assert_eq!(report.trusted.len(), 3, "membership is as it was");
        assert!(report.accepted.is_empty() && report.received.is_empty());
        for path in [requests(&o), device_file::device_path(&o.id)] {
            assert_eq!(reads(&kit, &path), 1, "{path}");
        }
        for path in [&changes, &overflow, &answer] {
            assert_eq!(reads(&kit, path), 0, "{path}");
        }
        let after = saved(&kit);
        assert!(before == after, "a pass saved something from a stranger");
    }

    #[test]
    fn a_request_alone_or_a_device_file_alone_is_reported_as_what_it_is() {
        let mut kit = testkit::library(2);
        let (a, b) = (outsider(&kit, "asks"), outsider(&kit, "writes"));
        put(&mut kit, &requests(&a), &a.request);
        put(&mut kit, &device_file::device_path(&b.id), &b.file);
        let report = kit.devices[0].pass();
        let find = |id| report.strangers.iter().find(|s| s.device == id).unwrap();
        assert_eq!((find(a.id).request, find(a.id).device_file), (true, None));
        assert_eq!(find(a.id).name, "asks");
        assert_eq!(
            (find(b.id).request, find(b.id).device_file),
            (false, Some(1))
        );
        // Without a request the key is the one the file names, held to its ID.
        assert_eq!(
            (find(b.id).name.as_str(), find(b.id).key),
            ("writes", b.key.public())
        );
        assert_eq!(report.strangers.len(), 2);
    }

    #[test]
    fn enrolled_devices_are_not_strangers_and_removed_ones_are_not_either() {
        let mut kit = testkit::library(3);
        let gone = kit.devices[2].lib.device;
        kit.remove(0, 2, None);
        let report = kit.devices[0].pass();
        assert!(
            report.strangers.is_empty() && report.set_aside.is_empty(),
            "{report:?}"
        );
        assert_eq!(reads(&kit, &device_file::device_path(&gone)), 0);
    }

    #[test]
    fn thirty_three_unknown_identities_are_thirty_two_read_and_one_counted() {
        // SY34: no more than 32 a pass, a request first, then by ID.
        let mut kit = testkit::library(2);
        let mut all: Vec<Outsider> = (0..33).map(|_| outsider(&kit, "n")).collect();
        for o in &all {
            put(&mut kit, &requests(o), &o.request);
            put(&mut kit, &device_file::device_path(&o.id), &o.file);
        }
        all.sort_by_key(|o| o.id);
        let report = kit.devices[0].pass();
        assert_eq!(report.stopped, None, "{report:?}");
        assert_eq!((report.strangers.len(), report.strangers_unread), (32, 1));
        for (i, o) in all.iter().enumerate() {
            let expected = usize::from(i < 32);
            assert_eq!(reads(&kit, &requests(o)), expected, "request {i}");
            assert_eq!(
                reads(&kit, &device_file::device_path(&o.id)),
                expected,
                "file {i}"
            );
        }
    }

    #[test]
    fn an_identity_with_a_request_is_read_before_ones_with_only_a_device_file() {
        let mut kit = testkit::library(2);
        let mut quiet: Vec<Outsider> = (0..33).map(|_| outsider(&kit, "n")).collect();
        quiet.sort_by_key(|o| o.id);
        let top = quiet.last().unwrap().id;
        let asking = loop {
            let o = outsider(&kit, "asks");
            if o.id > top {
                break o;
            }
        };
        for o in &quiet {
            put(&mut kit, &device_file::device_path(&o.id), &o.file);
        }
        put(&mut kit, &requests(&asking), &asking.request);
        let report = kit.devices[0].pass();
        assert_eq!((report.strangers.len(), report.strangers_unread), (32, 2));
        assert!(report.strangers.iter().any(|s| s.device == asking.id));
    }

    #[test]
    fn a_hostile_file_is_set_aside_and_changes_nothing() {
        // SP7, SY28: too large, not JSON, a signature that doesn't check, a request
        // that names another device, a request signed by a key that isn't its own.
        let mut kit = testkit::library(2);
        kit.devices[0].pass();
        let before = saved(&kit);
        let lib = kit.devices[0].lib.id;
        let [big, junk, forged, copied, wrong, fat] = [0; 6].map(|_| outsider(&kit, "x"));
        put(
            &mut kit,
            &device_file::device_path(&big.id),
            &vec![b' '; device_file::MAX_DEVICE_FILE + 1],
        );
        put(&mut kit, &device_file::device_path(&junk.id), b"not json");
        let mut tampered = forged.file.clone();
        let at = tampered
            .windows(7)
            .rposition(|w| w == br#""sig":""#)
            .unwrap()
            + 7;
        tampered[at] = if tampered[at] == b'A' { b'B' } else { b'A' };
        put(&mut kit, &device_file::device_path(&forged.id), &tampered);
        // Another's request under this ID's name, and a file naming a key not its ID's.
        put(&mut kit, &requests(&copied), &big.request);
        let other = Keypair::generate().unwrap();
        let bad = device_file::write(&other, &lib, &WRITER, 1, &Fields::default()).unwrap();
        put(&mut kit, &device_file::device_path(&wrong.id), &bad.bytes);
        put(
            &mut kit,
            &requests(&fat),
            &vec![b' '; enrollment::MAX_FILE + 1],
        );
        let report = kit.devices[0].pass();
        assert_eq!(report.stopped, None, "{report:?}");
        assert!(report.strangers.is_empty(), "{:?}", report.strangers);
        assert_eq!(report.set_aside.len(), 6, "{:?}", report.set_aside);
        for path in [device_file::device_path(&big.id), requests(&fat)] {
            assert_eq!(reads(&kit, &path), 0, "{path} is never read");
        }
        assert!(before == saved(&kit));
        assert_eq!(report.trusted.len(), 2);
    }

    #[test]
    fn each_budget_stops_the_reading_and_the_next_pass_goes_on() {
        let mut kit = testkit::library(2);
        let o = outsider(&kit, "n");
        put(&mut kit, &requests(&o), &o.request);
        put(&mut kit, &device_file::device_path(&o.id), &o.file);
        let count =
            |kit: &Kit, dir| kit.devices[0].folder.list(dir, None).unwrap().entries.len() as u64;
        // Names: the `enroll/` listing is past the budget.
        let mut b = Budgets::sy2();
        b.names = ["libraries", "trust", "devices"]
            .iter()
            .map(|d| count(&kit, d))
            .sum();
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(
            (report.stopped, report.strangers.len()),
            (Some(Stopped::Names), 0)
        );
        let before = report.bytes_read;
        // Bytes: the request is read, the budget is gone, and nothing is reported.
        b = Budgets::sy2();
        b.bytes = before + o.request.len() as u64 - 1;
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(
            (report.stopped, report.strangers.len()),
            (Some(Stopped::Bytes), 0)
        );
        assert_eq!(
            reads(&kit, &device_file::device_path(&o.id)),
            0,
            "the pass ended before the device file"
        );
        // Between the two reads the device file's read is the one that runs it out.
        b.bytes = before + (o.request.len() + o.file.len()) as u64 - 1;
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(report.stopped, Some(Stopped::Bytes));
        // Time: the clock jumps once `enroll/` is listed.
        let listed = Rc::new(Cell::new(0));
        let clock = || if listed.get() > 0 { 120_000 } else { 0 };
        let mut folder = Watched {
            inner: kit.folder.view(&kit.devices[0].lib.device.to_string()),
            watch: "enroll",
            listed: listed.clone(),
        };
        let report = kit.devices[0]
            .pass_over(&mut folder, READ, &Budgets::sy2(), &clock)
            .unwrap();
        assert_eq!(
            (report.stopped, report.strangers.len()),
            (Some(Stopped::Time), 0)
        );
        // Devices: a budget for enrolled devices doesn't count these (they have a cap
        // of their own), so a pass with room reads them.
        let report = kit.devices[0].pass();
        assert_eq!(
            (report.stopped, report.strangers.len()),
            (None, 1),
            "{report:?}"
        );
    }
}
