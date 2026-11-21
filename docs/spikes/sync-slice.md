# Sync B6: the slice over real iCloud Drive and Google Drive folders

- **Date:** 2026-11-21. `Mac18,5` (Apple M6, 24 GiB), macOS 27.2.1 (26B131), WebKit 22625.2.8.11.9. Google Drive for desktop 134.0 (File Provider). One Mac, no second Mac at hand.
- **Question (`docs/sync-delivery-plan.md`, B6, SD2–SD6):** whether the B5 slice (`SY-nothing-without-setup`, `SY-place-resume`, `SY-highlight-roundtrip`) passes through real `Linen-spike` folders in iCloud Drive and Google Drive using `sync::folder::Disk`, how long a change takes to upload and materialize, and what real File Provider folders do that `sync::folder::Memory` (PS2) has no switch for.
- **Raw results:** `raw/sync-slice.json` (account and home-folder names removed).

## Method (SD3)

With the owner's agreement (2026-11-21), the `--features spikes` build (`LINEN_SPIKE=sync`) ran two throwaway test libraries (`LINEN_DATA_DIR`) against:

1. A local temporary directory (baseline).
2. `~/Library/Mobile Documents/com~apple~CloudDocs/Linen-spike` (iCloud Drive).
3. `~/Library/CloudStorage/GoogleDrive-‹account›/My Drive/Linen-spike` (Google Drive).

`sync_slice.rs` refuses any `LINEN_SYNC_SPIKE_DIR` whose basename is not `Linen-spike` or that already contains files. Neither the reader's own Linen library nor any `Linen` sync folder was opened or modified. After each cloud run:

- A throwaway Swift probe (`URLResourceValues`, `lstat` `SF_DATALESS`, `listxattr`, deleted after the session) polled `ubiquitousItemIsUploaded` until all 18 files produced by the slice reached the cloud, and checked for hidden files, conflict copies, errors, and extended attributes.
- The probe evicted the 11 `devices/`, `changes/`, and `blobs/` files (`FileManager.evictUbiquitousItem`) and verified `SF_DATALESS` and `NSURLUbiquitousItemDownloadingStatusNotDownloaded`.
- `sync::folder::Disk` (`disk_reads_external_spike_dir_when_requested`) then listed, statted, and read all 14 files in `devices/`, `blobs/`, `trust/`, `libraries/`, and `changes/<device>/` directly from the real folder.
- Each `Linen-spike` folder was removed afterwards (`removed: true`, 3 ms each).

## Results

### 1. Slice checks and same-Mac pass timings

All three checks passed on every storage: `SY-nothing-without-setup`, `SY-place-resume` (exact CFI `epubcfi(/6/16!/4/2[chapter-2],/2,/6/1:595)` and fraction), and `SY-highlight-roundtrip` (exact quote anchor, `"made in A"` received in B, `"edited in B"` returned to A).

| Step (18 files total by end of run) | Local temp dir | iCloud Drive | Google Drive |
|---|---:|---:|---:|
| Setup (genesis, claim, enroll exchange; 7 files) | 59 ms | 59 ms | 57 ms |
| Pass A1 (publish place, highlight and note; +8 files) | 28 ms | 29 ms | 27 ms |
| Pass B1 (read A's changes & blobs, apply, publish B device file) | 9 ms | 10 ms | 8 ms |
| Pass B2 (publish edited note; +3 files) | 17 ms | 20 ms | 17 ms |
| Pass A2 (read B's change & blob, apply, update A device file) | 7 ms | 7 ms | 7 ms |
| Cleanup (`removeItem` on `Linen-spike`) | n/a | 3 ms | 3 ms |

On one Mac with hot local files, `folder::Disk` over both File Provider folders is indistinguishable in speed from local APFS (7–29 ms per pass).

### 2. Cloud upload and evicted-file materialization

Because both test libraries ran on one Mac, same-Mac passes read local File Provider cache before cloud round-trip. Two measurements bound what a second device actually sees:

- **Upload to cloud:**
  - **iCloud Drive:** all 18 files reported `isUbiquitous: true` and `isUploaded: true` on the first poll (~8 s after `passA2` exited), with zero errors or conflicts.
  - **Google Drive:** 14 files (`libraries/`, `trust/`, `enroll/`, `devices/`, `blobs/`) already reported `isUploaded: true` on the first poll, while the 4 files in the newly created nested `changes/<device>/` subdirectories finished uploading **2.78 s later** (all 18 `isUploaded: true`, zero errors or conflicts).
- **Reading evicted (`SF_DATALESS`) files through `folder::Disk`:**
  - Every evicted file (< 7 KB total across all 11 files; individual sizes 2 B to 1,856 B) stayed listed by `Disk::list`, reported its full `st_size` to `Disk::stat`, and **blocked synchronously inside `Disk::read`** while File Provider downloaded it, despite `Disk::read` passing `O_RDONLY | O_NONBLOCK`.

| Storage | Non-evicted files (`trust/`, `libraries/`, 3 files) | Evicted files (`devices/`, `changes/`, `blobs/`, 11 files) | Per-file range (median) |
|---|---:|---:|---:|
| iCloud Drive | 0 ms each | **16.04 s** total | 996–2,361 ms (**1,547 ms**) |
| Google Drive | 0 ms each | **16.40 s** total | 998–2,456 ms (**1,238 ms**) |

## What real folders did that `folder::Memory` (PS2) has no switch for

1. **Synchronous per-file blocking on evicted (`SF_DATALESS`) files (`SY30`, `SY2`) — gap in `Folder` and `Memory`:**
   - `folder::Disk::read` opens with `O_RDONLY | O_NONBLOCK`, which does **not** make macOS File Provider non-blocking on dataless items.
   - Even **online**, sequential reads of tiny evicted objects cost **1.0–2.5 s per file** on both iCloud Drive and Google Drive. A pass catching up on only 30–50 evicted change files and blobs will exhaust `SY2`'s 60-second pass budget; offline (Stage 0, `docs/spikes/sync-folders.md`), a single evicted Google Drive file blocked for 84.5 s (or returned `ETIMEDOUT` when Drive was quit).
   - `Folder::Read` currently has only `Bytes`, `TooLarge`, and `Gone` — no `Waiting` / `NotDownloaded` variant — and `folder::Memory` (PS2) has no switch for dataless/not-downloaded files or materialization latency. Any future Stage 2 / `Disk` implementation needs `SF_DATALESS` detection (`fstatat` `st_flags`), non-blocking `Waiting` status, and asynchronous download requests (`startDownloadingUbiquitousItem`) batched ahead of reads rather than sequential blocking opens.
2. **Directory-depth upload reordering (observed on Google Drive):**
   - `devices/<id>.json` (step 10, depth 1) finished uploading 2.78 s before `changes/<id>/000000000001..2.json` (step 9, depth 2, in a newly created subdirectory). A peer reading from a second device will therefore routinely see a device file whose `own` leads changes that have not yet appeared in `changes/<id>/`. `Memory::delay_visibility` already models per-path delay, so no new PS2 switch is required for this, though whole-subdirectory lag is a real trigger for that path.
3. **Extended attributes (no breakage, absent in `Memory`):**
   - iCloud Drive attached `com.apple.provenance`; Google Drive attached `com.apple.lastuseddate#PS`, `com.apple.provenance`, and `com.google.drivefs.item-id#S`. No hidden files (`.DS_Store`, leftover `.linen-tmp-*`) or conflict copies appeared in these sequential single-Mac runs.

## Not measured here

- Two-Mac end-to-end arrival time and concurrent-write conflict-copy names (`#174`): no second Mac was available.
- Offline or Drive-quit `Disk::read` behavior (already measured with standalone probes in Stage 0, `docs/spikes/sync-folders.md`).
- iPadOS folder viability (`#80`, `docs/sync-plan.md` §8 Risk 3).

## SD6 review gate — recommendation and outcome

- **Recommendation:** **Park sync** rather than investing in Part C (`C1`–`C7`). The slice works on hot local files, but B6 confirms that real File Provider eviction (`SF_DATALESS`) adds another substantial OS-integration layer (`Waiting` states, async download batching, offline/Drive-quit handling) on top of an already 55.6k-LOC Rust sync core (4.4× the rest of the Rust backend, 5/31 Stage 1 checks Covered, 0 release callers) targeting a Mac-only audience while iPadOS folder viability remains unverified.
- **Owner decision (2026-11-21):** **Approved — park sync in docs, leaving `src-tauri/src/sync/` dormant as-is.** No Part C stage (`P3b`, `P4a`, `P4b`, Stages 2–6) is labelled. Revisit only if a second platform (`#80` / `#54`) is committed and its storage model is validated, or if a much smaller single-user sync design is chosen later.
