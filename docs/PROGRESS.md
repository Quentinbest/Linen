# Progress

The state of each phase of `docs/implementation-plan.md` (§5), macOS only (scope decision, 2026-09-24).

This file is updated at every phase boundary. Before the next phase starts, the previous phase is checked against its Done-when list; the evidence is in its status document. Owner decisions waiting are in `docs/pending-approvals.md`; decisions taken are in `docs/decisions.md`.

| Phase | State | Done-when | Status document |
|---|---|---|---|
| 0 Spikes | Done | Spikes A–F reported; decisions recorded | `docs/spikes/` |
| 1 Foundations | Done | Met | (git history, `docs/decisions.md`) |
| 2 Reading | Done | Met | `docs/phase2-status.md` |
| 3 Navigation | Done | Met; baselines approved 2026-09-25 | `docs/phase3-status.md` |
| 4 Search | Done | Met; baseline approved 2026-09-25 | `docs/phase4-status.md` |
| 5 Selection and annotation | Done | Met; baselines approved 2026-09-25 | `docs/phase5-status.md` |
| 6 Settings and library | Done | Met; baselines approved 2026-09-25 | `docs/phase6-status.md` |
| 7 Extensions | Done | Verified 2026-09-25 (98/98 on Desktop 2); baselines and the P6 memory budget approved 2026-09-26 | `docs/phase7-status.md` |
| 8 Hardening and release | Done | 2026-09-26: 107/107 on Desktop 2; unit tests and budgets pass; CI passes on GitHub; every approval item settled (9, 10, 21–30) | `docs/phase8-status.md` |
| Release 1.1 (owner, 2026-10-01; without TTS, sync and Developer ID signing) | Done; approved 2026-10-01 (items 31, 33–41); released as 0.2.0 on 2026-10-02 | Each feature's in-app check passes; local and GitHub CI green | `docs/release-1.1-status.md` |
| Reader review (owner, 2026-10-06: jumps, the wheel over Contents, minimum size, Scroll-mode reveal) | Done; approved 2026-10-06 (items 53, 54); minimum window 760 × 480; released as 0.2.1 on 2026-10-06 | The owner's items reproduced with real input, then pass; full suite and local CI green | `docs/reader-review-2026-10-06.md` |
| Scroll bars (owner, 2026-10-07: the overlay scroll bar in a recording) | Done; approved 2026-10-07 (item 55, option A: follow macOS); no product change | Measured in the app with real input, with this Mac's setting and with overlay bars (`scrollbar-survey`); local CI green | `docs/scrollbar-survey-2026-10-07.md` |

## After the plan

| Work | State | Plan and status |
|---|---|---|
| UI localisation (zh-Hans, zh-Hant, ja, es; L-1 to L-11, 2026-10-07) | Done: four languages signed off and registered 2026-10-08; released as 0.3.0 on 2026-10-09 | `docs/i18n-plan.md` (stage table at its end) |
| Reading Lens (lookup peek, local dictionaries, optional hosts and keys; 2026-10-09) | Stages 2a, 2b and 2d released as 0.4.0 on 2026-10-11; Stage 1's diary ended 2026-10-26 with Gate 0 not measured (1 stuck point from 1 reader; the waiver stands); Stage 3's Explain is private (`linen-explain`) and its offline check waits for a later diary (item 117 (a)) | `docs/reading-lens-plan.md`, `docs/reading-lens-status.md` |
| Compact selection bar (owner, 2026-10-12: icons with tooltips, Explain as an icon, the two “Explain” entries, the extension's name) | Done 2026-10-13 (#35): local CI green, in-app suite 172/175 plus the three canary checks rerun once their port was free; items 88–96 approved 2026-10-13, captures are baselines; released as 0.5.0 on 2026-10-13 and tested by the owner; Explain 0.2.0 (“Reading Lens”) merged (`linen-explain` #2) | `docs/selection-bar-plan.md`, `docs/selection-bar-status.md` |
| Sync across devices (#73; owner, 2026-10-14: everything but extensions and dictionaries, through iCloud Drive and Google Drive folders) | **Parked at the SD6 review gate (owner, 2026-11-21).** Plan (#84), protocol (#101), Stage 0 (`docs/spikes/sync-folders.md`), Stage 1a–1c, and `docs/sync-delivery-plan.md` Parts A and B (`B1`–`B5`: #224, #228, #230, #232, #235, #236, #237, #243, #244; `B6`: `docs/spikes/sync-slice.md`) are done. B6 passed all three slice checks over temporary `Linen-spike` folders in iCloud Drive and Google Drive on one Mac, and confirmed that `SF_DATALESS` eviction blocks `folder::Disk::read` for ~1.0–2.5 s per tiny file despite `O_NONBLOCK` (~16 s for 11 files < 7 KB on both storages). Part C (`P3b`, `P4a`/`P4b`, Stages 2–6) is unlabelled and parked; `src-tauri/src/sync/` stays dormant with zero release-build callers (PS8). Revisit only if a second platform (#54, #80) is committed or a smaller single-user design is chosen | `docs/sync-plan.md`, `docs/sync-delivery-plan.md`, `docs/sync-status.md`, `docs/spikes/sync-slice.md` |

## How the work is checked

- **Unit tests.** `pnpm test` (Vitest) and `cargo test` (Rust); CI runs both on every push.
- **The in-app end-to-end suite.** `scripts/e2e.sh`, on the current desktop; `LINEN_SPACE=2` moves it to Desktop 2 (required 2026-09-25, optional since 2026-09-29). It has 124 checks in total (plus opt-in measurements such as `size-survey` and `scrollbar-survey`, run only by name; arguments after the check regex go to the app); the last fails on any uncaught error in the run. The safe-mode checks also run with `LINEN_SAFE_MODE=1`.
- **Visual captures.** `scripts/e2e.sh v`, compared with the approved baselines by `node tests/visual/compare.mjs`.
- **Budgets.** `scripts/perf-coldstart.py` and `scripts/perf-memory.sh`, on the reference machine.
