//! SP37 (3), SP18, SP26: a removed device's change files after its cutoff, read only
//! to list them (“Arrived from ‹device› after it was removed · Keep · Discard”,
//! SY34). Nothing in them is applied, fetched or kept: no body, no version, no
//! frontier, floor or saved state is touched, so the pass keeps nothing of a tail
//! between passes and reads it again each time (PROVISIONAL, decisions.md, item 128).
//! Each file is checked as that device's own, with the key membership kept for it
//! (`Membership::key`: a removed identity's changes up to its cutoff are still its
//! own), and must follow the cutoff's change (or be the first, when the removal names
//! none), the one before it, and the one after it, in sequence. A reader's Keep and
//! Discard, the late list (`late`) and reverting what this device applied past the
//! cutoff are P3a's.
//!
//! SP26's cap, 500 files or 64 MB of them per removed device, holds the listing;
//! when it is reached `End::Cap` says there are more. The reads of all tails together
//! take at most a quarter of a pass's byte budget (PROVISIONAL, `SHARE`), so that
//! removed devices' files, which step (3) reads before any enrolled peer's changes in
//! step (4), can't use a whole pass up.

use super::chain;
use super::folder::Folder;
use super::ids::{DeviceId, Hash32, Id16};
use super::late::{MAX_LATE, MAX_LATE_BYTES};
use super::membership::Membership;
use super::pass::{self, Budgets, Error, Meter, Report};
use super::trust::Mark;
use std::collections::BTreeMap;

/// PROVISIONAL: the part of `Budgets::bytes` all tails together may read.
pub const SHARE: u64 = 4;

/// How a removed device's listing ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// Storage holds no file after the last one listed.
    All,
    /// SP26's cap (files or bytes) was reached with another file in storage.
    Cap,
    /// The tails' share of the pass's byte budget was used up, with another file in
    /// storage.
    Share,
    /// The next file wouldn't read or check, or didn't follow: set aside in the
    /// report and read again on a later pass (SP7).
    Waits,
    /// A pass budget ran out; the files read before it are listed.
    Budget,
}

/// One change file of a removed device, after its cutoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailFile {
    pub seq: u64,
    pub hash: Hash32,
    /// The file's size.
    pub bytes: u64,
    /// How many versions it carries.
    pub versions: u64,
}

/// SP18, SP26: what a pass listed of one removed device's changes after its cutoff.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tail {
    pub device: DeviceId,
    /// The change the removal named; none when it named none.
    pub after: Option<Mark>,
    pub files: Vec<TailFile>,
    pub end: End,
}

/// SP18, SP26: lists the change files after each removed device's cutoff, in
/// sequence, within SP26's cap and the pass's budgets.
pub(super) fn read<F: Folder>(
    lib: &Id16,
    me: &DeviceId,
    folder: &F,
    membership: &Membership,
    meter: &Meter<'_>,
    report: &mut Report,
) -> Result<(), Error> {
    let share = meter.budgets().bytes / SHARE;
    let mut used = 0u64;
    for device in &membership.state.removed {
        let Some(key) = membership.key(device).filter(|_| device != me) else {
            continue;
        };
        let after = membership.state.cutoffs.get(device).copied().flatten();
        let Some(listing) = pass::list_all(folder, &format!("changes/{device}"), meter, report)?
        else {
            return Ok(());
        };
        let listing: BTreeMap<_, _> = listing.into_iter().map(|e| (e.name.clone(), e)).collect();
        let (mut seq, mut prev) = (after.map_or(1, |m| m.s + 1), after.map(|m| m.h));
        let mut tail = Tail {
            device: *device,
            after,
            files: Vec::new(),
            end: End::All,
        };
        let (max_files, max_bytes) = caps(meter.budgets());
        let mut size = 0u64;
        loop {
            let path = chain::change_path(device, seq);
            let Some(entry) = listing.get(&path) else {
                break;
            };
            if tail.files.len() as u64 >= max_files || size >= max_bytes {
                tail.end = End::Cap;
                break;
            }
            if used >= share {
                tail.end = End::Share;
                break;
            }
            let Some(bytes) = pass::read_bytes(folder, entry, report)? else {
                tail.end = End::Waits;
                break;
            };
            used += bytes.len() as u64;
            size += bytes.len() as u64;
            match chain::open_change(&bytes, lib, device, &key) {
                Ok(c) if c.seq == seq && c.prev == prev => {
                    tail.files.push(TailFile {
                        seq,
                        hash: c.hash,
                        bytes: bytes.len() as u64,
                        versions: c.versions.len() as u64,
                    });
                    prev = Some(c.hash);
                    seq += 1;
                }
                Ok(_) => {
                    report
                        .set_aside
                        .push((path, "doesn't follow its chain".into()));
                    tail.end = End::Waits;
                    break;
                }
                Err(e) => {
                    report.set_aside.push((path, format!("{e}")));
                    tail.end = End::Waits;
                    break;
                }
            }
            if let Some(stop) = meter.check(report) {
                report.stopped = Some(stop);
                tail.end = End::Budget;
                break;
            }
        }
        if !tail.files.is_empty() || tail.end != End::All {
            report.tails.push(tail);
        }
        if report.stopped.is_some() {
            return Ok(());
        }
    }
    Ok(())
}

/// SP26's cap, which a caller's budgets may only lower.
fn caps(budgets: &Budgets) -> (u64, u64) {
    (
        budgets.tail_files.min(MAX_LATE as u64),
        budgets.tail_bytes.min(MAX_LATE_BYTES),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AnnotationRow;
    use crate::sync::apply::tests::{highlight, note_of};
    use crate::sync::pass::{Budgets, Stopped};
    use crate::sync::testkit::{self, Kit, Watched, READ};
    use crate::sync::{apply, files};
    use std::cell::Cell;
    use std::rc::Rc;

    /// The removed device's `n` changes, each with `extra` highlights besides its note.
    fn publish(kit: &mut Kit, gone: usize, n: i64, extra: i64) {
        let kd = &mut kit.devices[gone];
        for k in 1..=n {
            for i in 0..extra {
                let row = AnnotationRow {
                    id: format!("{:08x}-6f7a-4b1c-9d2e-4f5a6b7c8d9e", k * 1000 + i),
                    cfi_range: format!("epubcfi(/6/4!/4/{},/1:0,/1:4)", 2 * (k * 1000 + i) + 10),
                    ..highlight("book", Some("kept"), 1_760_000_000_500)
                };
                kd.db.save_annotation(&row).unwrap();
            }
            let note = format!("note {k}");
            kd.db
                .save_annotation(&highlight("book", Some(&note), 1_760_000_001_000 + k))
                .unwrap();
            kd.publish_pending().unwrap();
        }
    }

    fn seqs(report: &Report) -> Vec<u64> {
        report.tails[0].files.iter().map(|f| f.seq).collect()
    }

    /// How many times the first device read `path`.
    fn reads(kit: &Kit, path: &str) -> usize {
        kit.folder
            .read_count(&kit.devices[0].lib.device.to_string(), path)
    }

    /// Three devices; the last has published `n` changes and is removed by the first
    /// with a cutoff at its change `at` (none for 0).
    fn removed(n: i64, extra: i64, at: u64) -> (Kit, DeviceId) {
        let mut kit = testkit::library(3);
        publish(&mut kit, 2, n, extra);
        let gone = kit.devices[2].lib.device;
        let cutoff = (at > 0).then(|| (at, kit.devices[2].own_changes(at)[at as usize - 1].hash));
        kit.remove(0, 2, cutoff);
        (kit, gone)
    }

    #[test]
    fn a_removed_devices_changes_after_its_cutoff_are_listed_and_not_applied() {
        // SP18, SP26: changes 2 and 3 are after the cutoff at 1: listed, read once a
        // pass, applied by nobody; change 1 is before it and isn't read.
        let (mut kit, gone) = removed(3, 0, 1);
        let report = kit.devices[0].pass();
        assert_eq!(report.stopped, None, "{report:?}");
        assert!(!report.trusted.contains(&gone));
        assert_eq!(report.tails.len(), 1, "{report:?}");
        let tail = &report.tails[0];
        assert_eq!((tail.device, tail.end), (gone, End::All));
        assert_eq!(tail.after.map(|m| m.s), Some(1));
        assert_eq!(seqs(&report), vec![2, 3]);
        assert!(tail.files.iter().all(|f| f.versions == 1 && f.bytes > 0));
        assert!(report.received.is_empty() && report.behind.is_empty());
        assert_eq!(note_of(&kit.devices[0].db, "book"), None);
        assert_eq!(
            apply::seen(kit.devices[0].db.conn(), &kit.devices[0].lib, gone).unwrap(),
            0
        );
        for (s, expected) in [(1, 0), (2, 1), (3, 1)] {
            let path = chain::change_path(&gone, s);
            assert_eq!(reads(&kit, &path), expected, "change {s}");
        }
        // Nothing is kept: the tail is read again, and nothing else moves.
        let (store, state) = (kit.devices[0].store.clone(), snapshot(&kit));
        assert_eq!(kit.devices[0].pass().tails, report.tails);
        assert_eq!(reads(&kit, &chain::change_path(&gone, 3)), 2);
        assert!(kit.devices[0].store == store && snapshot(&kit) == state);
    }

    /// What the pass saves of the first device, to show a pass changed none of it.
    fn snapshot(kit: &Kit) -> serde_json::Value {
        let kd = &kit.devices[0];
        let s = crate::sync::pass::State::load(kd.db.conn(), &kd.lib.id).unwrap();
        serde_json::json!([
            s.membership,
            s.heard,
            s.ledger,
            s.objects,
            s.views,
            s.sigs,
            s.weeks,
            s.marks,
            s.ages
        ])
    }

    #[test]
    fn a_removal_naming_no_cutoff_lists_from_the_first_change() {
        let (mut kit, _) = removed(3, 0, 0);
        let report = kit.devices[0].pass();
        assert_eq!(seqs(&report), vec![1, 2, 3]);
        assert_eq!(report.tails[0].after, None);
    }

    #[test]
    fn a_file_that_doesnt_follow_the_cutoff_is_set_aside() {
        // SP18: the first file after the cutoff must be the one that follows it.
        let mut kit = testkit::library(3);
        publish(&mut kit, 2, 3, 0);
        kit.remove(0, 2, Some((1, Hash32([9; 32]))));
        let report = kit.devices[0].pass();
        assert_eq!(report.tails.len(), 1);
        assert!(report.tails[0].files.is_empty());
        assert_eq!(report.tails[0].end, End::Waits);
        assert!(report
            .set_aside
            .iter()
            .any(|(p, _)| p.ends_with("000000000002.json")));
        assert_eq!(
            reads(&kit, &chain::change_path(&kit.devices[2].lib.device, 3)),
            0
        );
    }

    #[test]
    fn a_file_that_fails_its_check_ends_the_tail() {
        // SP7, SP14: a half-synced or forged file is set aside and read again later;
        // what came before it is listed, what comes after it isn't.
        let (mut kit, gone) = removed(3, 0, 1);
        let path = chain::change_path(&gone, 3);
        let list = kit.devices[2]
            .folder
            .list(&format!("changes/{gone}"), None)
            .unwrap();
        let entry = list.entries.into_iter().find(|e| e.name == path).unwrap();
        let files::Read::Bytes(mut bytes) =
            files::read_file(&kit.devices[2].folder, &entry).unwrap()
        else {
            panic!()
        };
        let at = bytes.windows(7).rposition(|w| w == br#""sig":""#).unwrap() + 7;
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        kit.devices[2].folder.write(&path, &bytes).unwrap();
        let report = kit.devices[0].pass();
        assert_eq!(seqs(&report), vec![2]);
        assert_eq!(report.tails[0].end, End::Waits);
        assert!(report.set_aside.iter().any(|(p, _)| *p == path));
        // An over-large file is set aside unread.
        kit.devices[2]
            .folder
            .write(&path, &vec![b' '; chain::MAX_CHANGE_BYTES + 1])
            .unwrap();
        let report = kit.devices[0].pass();
        assert_eq!(seqs(&report), vec![2]);
        assert!(report
            .set_aside
            .iter()
            .any(|(p, why)| *p == path && why == "over its limit"));
        assert_eq!(reads(&kit, &path), 1, "only the first was read");
        assert_eq!(note_of(&kit.devices[0].db, "book"), None);
    }

    #[test]
    fn sp26s_cap_holds_the_listing() {
        let (mut kit, _) = removed(4, 0, 0);
        let mut b = Budgets::sy2();
        // Files: the third file is there, so the listing is cut, not ended.
        b.tail_files = 2;
        let report = kit.devices[0].pass_with(&b);
        assert_eq!((seqs(&report), report.tails[0].end), (vec![1, 2], End::Cap));
        // Exactly the cap with nothing beyond it is not a cut one.
        b.tail_files = 4;
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(
            (seqs(&report), report.tails[0].end),
            (vec![1, 2, 3, 4], End::All)
        );
        // Bytes: past the first file's size, no more is read.
        b.tail_files = 500;
        b.tail_bytes = report.tails[0].files[0].bytes;
        let report = kit.devices[0].pass_with(&b);
        assert_eq!((seqs(&report), report.tails[0].end), (vec![1], End::Cap));
        // A caller's budgets can lower SP26's cap, not raise it.
        b.tail_files = u64::MAX;
        b.tail_bytes = u64::MAX;
        assert_eq!(caps(&b), (500, 64 << 20));
    }

    #[test]
    fn all_tails_together_take_a_quarter_of_the_byte_budget() {
        // PROVISIONAL, `SHARE`: the pass's own reads first, then at most a quarter.
        let (mut kit, _) = removed(3, 12, 0);
        let everything = kit.devices[0].pass();
        let first = everything.tails[0].files[0].bytes;
        assert_eq!(everything.tails[0].end, End::All);
        let mut b = Budgets::sy2();
        b.bytes = everything.bytes_read;
        assert!(b.bytes / SHARE <= first, "the fixture must be big enough");
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(report.stopped, None, "{report:?}");
        assert_eq!((seqs(&report), report.tails[0].end), (vec![1], End::Share));
    }

    #[test]
    fn each_budget_stops_the_tails_and_the_next_pass_goes_on() {
        let (mut kit, _) = removed(3, 0, 0);
        let whole = kit.devices[0].pass();
        let count =
            |kit: &Kit, dir| kit.devices[0].folder.list(dir, None).unwrap().entries.len() as u64;
        // Names: the removed device's directory is listed past the budget.
        let mut b = Budgets::sy2();
        b.names = ["libraries", "trust", "devices", "enroll"]
            .iter()
            .map(|d| count(&kit, d))
            .sum();
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(
            (report.stopped, report.tails.len()),
            (Some(Stopped::Names), 0)
        );
        // Bytes: what was read before the removed device's directory was listed, and
        // the first file: the pass is over once that is read, and it is listed.
        let first = whole.tails[0].files[0].bytes;
        b = Budgets::sy2();
        b.bytes = report.bytes_read + first - 1;
        let report = kit.devices[0].pass_with(&b);
        assert_eq!(report.stopped, Some(Stopped::Bytes));
        assert_eq!((seqs(&report), report.tails[0].end), (vec![1], End::Budget));
        // Time: the clock jumps once a removed device's directory is listed.
        let listed = Rc::new(Cell::new(0));
        let clock = || if listed.get() > 0 { 120_000 } else { 0 };
        let mut folder = Watched {
            inner: kit.folder.view(&kit.devices[0].lib.device.to_string()),
            watch: "changes/",
            listed: listed.clone(),
        };
        let report = kit.devices[0]
            .pass_over(&mut folder, READ, &Budgets::sy2(), &clock)
            .unwrap();
        assert_eq!(
            (report.stopped, report.tails.len()),
            (Some(Stopped::Time), 0)
        );
        // The next pass, with room, lists them all.
        assert_eq!(seqs(&kit.devices[0].pass()), vec![1, 2, 3]);
    }
}
