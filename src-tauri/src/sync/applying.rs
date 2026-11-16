//! SP37 (6): apply the small records received by the pass.

use super::ids::{DeviceId, Hash32};
use super::pass::{Device, Error, Report, SignedMark};
use super::{apply, backup, chain, guard, journal, pass, views};

pub(super) struct Run {
    pub peer: DeviceId,
    pub key: [u8; 32],
    pub have: u64,
    pub floor: Vec<(u64, Hash32)>,
    pub last_sig: Option<SignedMark>,
    pub taken: Option<views::Opened>,
    pub files: Vec<(Vec<u8>, Vec<Vec<u8>>)>,
}

pub(super) fn apply_all(
    device: &mut Device<'_>,
    report: &mut Report,
    naming: &[u8; 32],
    runs: Vec<Run>,
    membership: &super::membership::Membership,
    now_ms: i64,
) -> Result<(), Error> {
    let result = apply_step(device, report, naming, runs, membership, now_ms);
    if result.is_err() {
        let db = device.db;
        device.state = pass::State::load(&*db.lock()?, &device.lib.id)?;
    }
    result
}

fn apply_step(
    device: &mut Device<'_>,
    report: &mut Report,
    naming: &[u8; 32],
    runs: Vec<Run>,
    membership: &super::membership::Membership,
    now_ms: i64,
) -> Result<(), Error> {
    let db = device.db;
    let conn = db.lock()?;
    pass::at(pass::Point::Locked, &conn)?;
    report.paused = guard::paused(&conn, &device.lib)?;
    report.asking = guard::asking(&conn, &device.lib)?;
    if report.paused {
        return Ok(());
    }
    for run in &runs {
        if let Some(mark) = &run.last_sig {
            device
                .state
                .sigs
                .peers
                .entry(run.peer)
                .or_default()
                .candidate = Some(mark.clone());
        }
    }
    pass::save_state_in(device, &conn)?;
    let stalled = guard::stalled(&conn, &device.lib)?;
    let mut deletes = Vec::new();
    for run in &runs {
        if let Some(view) = &run.taken {
            for shard in &view.view.shards {
                let versions: Vec<_> = shard.records.iter().map(|r| r.version.clone()).collect();
                deletes.extend(backup::deleted_keys(&versions));
            }
        }
        for (bytes, _) in &run.files {
            if let Ok(change) = chain::open_change(bytes, &device.lib.id, &run.peer, &run.key) {
                deletes.extend(backup::deleted_keys(&change.versions));
            }
        }
    }
    let removed: std::collections::BTreeMap<_, _> = membership
        .state
        .removed
        .iter()
        .map(|d| (*d, membership.state.cutoffs.get(d).copied().flatten()))
        .collect();
    let quarantined = device.state.membership.quarantined.clone();
    if !removed.is_empty() || !quarantined.is_empty() {
        let keys: Vec<String> = conn
            .prepare(
                "SELECT DISTINCT key FROM sync_versions WHERE library = ?1 AND seq IS NOT NULL",
            )?
            .query_map([device.lib.id.to_string()], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        deletes.extend(
            keys.iter()
                .filter_map(|k| super::record::Key::parse(k).map(|(k, _)| k)),
        );
    }
    if !runs.is_empty()
        || !removed.is_empty()
        || !quarantined.is_empty()
        || apply::can_move(&conn, &device.lib, now_ms)?
    {
        report.backup = backup::before_pass(&conn, device.root, &device.lib, &deletes, now_ms)?
            .map(|b| b.path.display().to_string());
    }
    pass::at(pass::Point::BackedUp, &conn)?;
    let unit = journal::Unit::begin(&conn)?;
    let accepted = super::frontier::stored_marks(
        device
            .store
            .library(&device.lib.id)
            .ok_or(Error::NoIdentity)?,
    )?;
    super::late::revert_past(&unit, &device.lib, &removed, &accepted, "removed", now_ms)?;
    super::late::revert_past(
        &unit,
        &device.lib,
        &quarantined,
        &accepted,
        "quarantined",
        now_ms,
    )?;
    if !stalled {
        report.late.applied = apply::apply_pending(&unit, &device.lib, now_ms)?;
    }
    let mut landed = Vec::new();
    let mut settled = Vec::new();
    for run in runs {
        if guard::stalled(&unit, &device.lib)? {
            break;
        }
        if let Some(view) = run.taken {
            let got = views::apply(
                device, &unit, naming, &run.peer, &run.key, view, run.files, now_ms,
            )?;
            let stopped = got.held_back();
            landed.push((run.peer, got));
            settled.push((run.peer, run.have));
            if stopped {
                break;
            }
        } else {
            match chain::receive_run(
                &unit,
                &device.lib,
                &run.peer,
                &run.key,
                &run.floor,
                run.files,
                now_ms,
            ) {
                Ok(_) => settled.push((run.peer, run.have)),
                Err(e @ chain::ChainError::Journal(_)) => return Err(e.into()),
                Err(e) => report
                    .set_aside
                    .push((format!("changes/{}", run.peer), e.to_string())),
            }
        }
    }
    // SY17: start the vouched clock for every deletion actually recorded by
    // restore::seen. Existing entries retain their original first-seen time.
    let deleted: Vec<(String, i64, String)> = unit
        .prepare(
            "SELECT device, seq, hash FROM sync_deleted WHERE library = ?1 AND seq IS NOT NULL",
        )?
        .query_map([device.lib.id.to_string()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<Result<_, _>>()?;
    let vouched = device.state.vouched.now();
    for (writer, seq, hash) in deleted {
        if let (Some(device_id), Some(hash)) = (DeviceId::parse(&writer), Hash32::parse(&hash)) {
            if let Ok(seq) = u64::try_from(seq) {
                device.state.ages.saw(
                    super::record::Entry {
                        device: device_id,
                        seq,
                        hash,
                    },
                    vouched,
                );
            }
        }
    }
    pass::save_state_in(device, &unit)?;
    pass::at(pass::Point::Applied, &conn)?;
    unit.commit()?;
    drop(conn);
    let conn = db.lock()?;
    pass::at(pass::Point::Committed, &conn)?;
    drop(conn);
    for (peer, got) in landed {
        views::finish(device, report, naming, &peer, got)?;
    }
    for (peer, have) in settled {
        pass::settle(device, report, peer, have)?;
    }
    let conn = db.lock()?;
    report.asking = guard::asking(&conn, &device.lib)?;
    report.paused = guard::paused(&conn, &device.lib)?;
    Ok(())
}
