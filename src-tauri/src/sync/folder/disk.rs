//! SY2, SD4: local storage rooted at an open directory descriptor.

use super::{ours, valid_path, Folder, Listed, Page, Read};
use std::{
    cell::RefCell,
    ffi::{CStr, CString},
    fs::{File, OpenOptions},
    io::{self, Read as _, Write},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
};

const PAGE_SIZE: usize = 1_000;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DiskToken {
    origin: [u8; 16],
    dir: String,
    name: String,
}

pub struct Disk {
    root: File,
    origin: [u8; 16],
    listing: RefCell<Option<Listing>>,
}

struct Listing {
    dir: String,
    cursor: String,
    stream: Directory,
}

fn random<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("writing to String");
    }
    result
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn name(value: &str) -> io::Result<CString> {
    CString::new(value).map_err(|_| invalid("NUL in name"))
}

fn syscall(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn open_at(dir: i32, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: the name is NUL-terminated. A successful call transfers a fresh fd.
    let fd = syscall(unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    })?;
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn stat_at(dir: i32, name: &CStr) -> io::Result<Option<libc::stat>> {
    let mut stat = MaybeUninit::uninit();
    // SAFETY: fstatat writes to valid uninitialized storage and never follows the leaf.
    match syscall(unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }) {
        Ok(_) => Ok(Some(unsafe { stat.assume_init() })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn regular(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
}

struct Directory(*mut libc::DIR);

impl Directory {
    fn open(dir: File) -> io::Result<Self> {
        // SAFETY: fdopendir takes ownership only on success.
        let stream = unsafe { libc::fdopendir(dir.as_raw_fd()) };
        if stream.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _ = dir.into_raw_fd();
        Ok(Self(stream))
    }

    fn next(&mut self, remaining: &mut usize) -> io::Result<Option<String>> {
        while *remaining > 0 {
            // SAFETY: this owns the stream, and entry bytes are copied before readdir
            // can invalidate them. Clearing errno distinguishes EOF from an error.
            unsafe {
                let errno = libc::__error();
                *errno = 0;
                let entry = libc::readdir(self.0);
                if entry.is_null() {
                    return if *errno == 0 {
                        Ok(None)
                    } else {
                        Err(io::Error::from_raw_os_error(*errno))
                    };
                }
                let raw = CStr::from_ptr((*entry).d_name.as_ptr());
                if raw == c"." || raw == c".." {
                    continue;
                }
                *remaining -= 1;
                let Ok(value) = raw.to_str() else { continue };
                if value.starts_with('.') || value.len() > 255 {
                    continue;
                }
                let fd = syscall(libc::dirfd(self.0))?;
                if stat_at(fd, raw)?.is_some_and(|stat| regular(&stat)) {
                    return Ok(Some(value.to_owned()));
                }
            }
        }
        Ok(None)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // SAFETY: this is the one owner of the stream and its descriptor.
        unsafe { libc::closedir(self.0) };
    }
}

impl Disk {
    /// The host supplies the selected, existing Linen directory. No operation
    /// resolves a path relative to the process working directory after this.
    pub fn open(root: &Path) -> io::Result<Self> {
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)?;
        Ok(Self {
            root,
            origin: random()?,
            listing: RefCell::new(None),
        })
    }

    fn directory(&self, dir: &str, create: bool) -> io::Result<File> {
        // Open a fresh file description so listings do not share directory offsets.
        let flags = libc::O_RDONLY | libc::O_DIRECTORY;
        let mut current = open_at(self.root.as_raw_fd(), c".", flags)?;
        if !dir.is_empty() {
            for part in dir.split('/') {
                let child = name(part)?;
                let fd = current.as_raw_fd();
                current = match open_at(fd, &child, flags) {
                    Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                        // SAFETY: child is a single validated segment under fd.
                        match syscall(unsafe { libc::mkdirat(fd, child.as_ptr(), 0o700) }) {
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                            Err(e) => return Err(e),
                        }
                        open_at(fd, &child, flags)?
                    }
                    result => result?,
                };
            }
        }
        Ok(current)
    }

    fn token(&self, token: &DiskToken) -> io::Result<Option<(File, CString)>> {
        if self.origin != token.origin {
            return Err(invalid("foreign token"));
        }
        match self.directory(&token.dir, false) {
            Ok(dir) => Ok(Some((dir, name(&token.name)?))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Folder for Disk {
    type Token = DiskToken;

    fn list(&self, dir: &str, cursor: Option<&str>) -> io::Result<Page<DiskToken>> {
        if !dir.is_empty() && (!valid_path(dir) || dir.split('/').count() >= 4) {
            return Err(invalid("invalid directory"));
        }
        let mut saved = self.listing.borrow_mut();
        let mut listing = if let Some(cursor) = cursor {
            if !saved
                .as_ref()
                .is_some_and(|l| l.dir == dir && l.cursor == cursor)
            {
                return Err(invalid("invalid cursor"));
            }
            saved.take().expect("cursor matched")
        } else {
            *saved = None;
            let folder = match self.directory(dir, false) {
                Ok(folder) => folder,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Ok(Page {
                        entries: Vec::new(),
                        next: None,
                    });
                }
                Err(e) => return Err(e),
            };
            Listing {
                dir: dir.to_owned(),
                cursor: String::new(),
                stream: Directory::open(folder)?,
            }
        };
        let mut entries = Vec::new();
        // Bound work even when the directory is full of hidden or special files.
        let mut remaining = PAGE_SIZE;
        while let Some(leaf) = listing.stream.next(&mut remaining)? {
            let name = if dir.is_empty() {
                leaf.clone()
            } else {
                format!("{dir}/{leaf}")
            };
            entries.push(Listed {
                ours: ours(&name),
                name,
                token: DiskToken {
                    origin: self.origin,
                    dir: dir.to_owned(),
                    name: leaf,
                },
            });
        }
        if remaining > 0 {
            return Ok(Page {
                entries,
                next: None,
            });
        }
        listing.cursor = hex(&random::<16>()?);
        let next = Some(listing.cursor.clone());
        *saved = Some(listing);
        Ok(Page { entries, next })
    }

    fn stat(&self, token: &DiskToken) -> io::Result<Option<u64>> {
        let Some((dir, leaf)) = self.token(token)? else {
            return Ok(None);
        };
        match stat_at(dir.as_raw_fd(), &leaf)? {
            Some(stat) if regular(&stat) => Ok(Some(stat.st_size as u64)),
            Some(_) => Err(invalid("token no longer names a regular file")),
            None => Ok(None),
        }
    }

    fn read(&self, token: &DiskToken, limit: Option<u64>) -> io::Result<Read> {
        let Some((dir, leaf)) = self.token(token)? else {
            return Ok(Read::Gone);
        };
        let file = match open_at(dir.as_raw_fd(), &leaf, libc::O_RDONLY | libc::O_NONBLOCK) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Read::Gone),
            Err(e) => return Err(e),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("token no longer names a regular file"));
        }
        let mut bytes = Vec::new();
        if let Some(limit) = limit {
            if metadata.len() > limit {
                return Ok(Read::TooLarge);
            }
            file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > limit {
                return Ok(Read::TooLarge);
            }
        } else {
            (&file).read_to_end(&mut bytes)?;
        }
        Ok(Read::Bytes(bytes))
    }

    fn write(&mut self, path: &str, bytes: &[u8]) -> io::Result<()> {
        if !valid_path(path) {
            return Err(invalid("invalid write path"));
        }
        let (dir, leaf) = path.rsplit_once('/').unwrap_or(("", path));
        let dir = self.directory(dir, true)?;
        let fd = dir.as_raw_fd();
        let leaf = name(leaf)?;
        if stat_at(fd, &leaf)?.is_some_and(|stat| !regular(&stat)) {
            return Err(invalid("write target is not a regular file"));
        }
        let temp = name(&format!(".linen-tmp-{}", hex(&random::<8>()?)))?;
        let mut staged = open_at(fd, &temp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)?;
        staged.write_all(bytes)?;
        staged.sync_all()?;
        // SAFETY: both names are single components in this same open directory.
        // renameat replaces a leaf symlink if it raced the check, never its target.
        syscall(unsafe { libc::renameat(fd, temp.as_ptr(), fd, leaf.as_ptr()) })?;
        Ok(())
    }

    fn remove(&mut self, token: &DiskToken) -> io::Result<()> {
        let Some((dir, leaf)) = self.token(token)? else {
            return Ok(());
        };
        let fd = dir.as_raw_fd();
        match stat_at(fd, &leaf)? {
            None => return Ok(()),
            Some(stat) if !regular(&stat) => {
                return Err(invalid("token no longer names a regular file"))
            }
            Some(_) => {}
        }
        // SAFETY: unlinkat removes a single leaf and does not follow a symlink.
        match syscall(unsafe { libc::unlinkat(fd, leaf.as_ptr(), 0) }) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::files;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn paths_and_tokens_stay_inside_the_open_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("note"), b"outside").unwrap();
        let mut disk = Disk::open(root.path()).unwrap();
        disk.write("in/note", b"inside").unwrap();
        let token = disk.list("in", None).unwrap().entries.remove(0).token;
        assert!(Disk::open(root.path()).unwrap().read(&token, None).is_err());
        for path in [
            "/note",
            "../note",
            "in/../note",
            "a/b/c/d/e",
            ".hidden",
            "a//b",
            &"a".repeat(256),
        ] {
            assert!(disk.write(path, b"bad").is_err(), "{path}");
        }
        fs::write(root.path().join(".hidden"), b"hidden").unwrap();
        symlink(outside.path(), root.path().join("outside")).unwrap();
        symlink(root.path().join("in"), root.path().join("inside")).unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        symlink(root.path().join("in/note"), root.path().join("sub/link")).unwrap();
        assert!(Disk::open(&root.path().join("outside")).is_err());
        for dir in ["outside", "inside"] {
            assert!(disk.list(dir, None).is_err());
            assert!(disk.write(&format!("{dir}/note"), b"bad").is_err());
        }
        assert!(disk.list("", None).unwrap().entries.is_empty());
        assert!(disk.list("sub", None).unwrap().entries.is_empty());
        assert!(disk.write("sub/link", b"bad").is_err());
        fs::remove_file(root.path().join("in/note")).unwrap();
        symlink(outside.path().join("note"), root.path().join("in/note")).unwrap();
        assert!(disk.read(&token, None).is_err());
        assert!(disk.stat(&token).is_err());
        assert!(disk.remove(&token).is_err());
        assert_eq!(fs::read(outside.path().join("note")).unwrap(), b"outside");

        fs::rename(root.path().join("in"), root.path().join("old-in")).unwrap();
        symlink(outside.path(), root.path().join("in")).unwrap();
        assert!(disk.read(&token, None).is_err());
        assert!(disk.remove(&token).is_err());
        assert_eq!(fs::read(outside.path().join("note")).unwrap(), b"outside");
    }

    #[test]
    fn sp7_conflict_copy_bounds_and_atomic_replacement() {
        let root = tempfile::tempdir().unwrap();
        let mut disk = Disk::open(root.path()).unwrap();
        let stem = "ab".repeat(16);
        let path = format!("libraries/{stem}.json");
        let copy = format!("libraries/{stem} 2.json");
        files::write_file(&mut disk, &path, b"first").unwrap();
        let old = File::open(root.path().join(&path)).unwrap();
        files::write_file(&mut disk, &path, b"second").unwrap();
        let mut old_contents = Vec::new();
        (&old).read_to_end(&mut old_contents).unwrap();
        assert_eq!(
            old_contents, b"first",
            "replacement kept the original inode intact"
        );
        fs::write(root.path().join(&copy), b"candidate").unwrap();
        fs::write(
            root.path().join("libraries/.linen-tmp-0000000000000001"),
            b"staged",
        )
        .unwrap();
        let entries = disk.list("libraries", None).unwrap().entries;
        assert_eq!(entries.len(), 2);
        let primary = entries.iter().find(|e| e.name == path).unwrap();
        let candidate = entries.iter().find(|e| e.name == copy).unwrap();
        assert!(primary.ours);
        assert!(!candidate.ours);
        assert_eq!(
            files::read_file(&disk, primary).unwrap(),
            files::Read::Bytes(b"second".to_vec())
        );
        assert_eq!(
            files::read_file(&disk, candidate).unwrap(),
            files::Read::Candidate { of: path.clone() }
        );
        assert_eq!(
            files::read_candidate(&disk, candidate).unwrap(),
            files::Read::Bytes(b"candidate".to_vec())
        );
        assert!(disk.write(&copy, b"not a writable path").is_err());
        assert_eq!(disk.stat(&primary.token).unwrap(), Some(6));
        fs::write(root.path().join(&path), vec![0; 4097]).unwrap();
        assert_eq!(
            disk.read(&primary.token, Some(4096)).unwrap(),
            Read::TooLarge
        );
        assert_eq!(
            files::read_file(&disk, primary).unwrap(),
            files::Read::TooLarge
        );
        assert!(files::write_file(&mut disk, &path, &[0; 4097]).is_err());
        disk.remove(&candidate.token).unwrap();
        disk.remove(&candidate.token).unwrap();
        assert_eq!(disk.read(&candidate.token, None).unwrap(), Read::Gone);
    }

    #[test]
    fn directory_listing_pages_are_bounded_and_cursors_are_scoped() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("files")).unwrap();
        for n in 0..1001 {
            fs::write(root.path().join(format!("files/{n}")), []).unwrap();
        }
        let disk = Disk::open(root.path()).unwrap();
        let first = disk.list("files", None).unwrap();
        assert_eq!(first.entries.len(), 1000);
        let cursor = first.next.unwrap();
        assert!(disk.list("", Some(&cursor)).is_err());
        let second = disk.list("files", Some(&cursor)).unwrap();
        assert_eq!(second.entries.len(), 1);
        assert!(second.next.is_none());
        assert!(first
            .entries
            .iter()
            .all(|e| e.name != second.entries[0].name));
        assert!(disk.list("files", Some(&cursor)).is_err());
    }

    #[test]
    fn shared_tidy_rejects_damaged_copy_and_recovers_from_verified_copy() {
        use crate::sync::{crypto::blob_name, ids::identity_hash, shared};
        let root = tempfile::tempdir().unwrap();
        let mut disk = Disk::open(root.path()).unwrap();
        let naming = [17; 32];
        let name = blob_name(&naming, &identity_hash(b"complete"));
        let path = format!("blobs/{name}");
        let copy = root.path().join(format!("{path}-conflict"));
        files::write_file(&mut disk, &path, b"damaged").unwrap();
        fs::write(&copy, b"partial").unwrap();
        let actions = shared::tidy(
            &mut files::Shared { folder: &mut disk },
            shared::Area::Blobs,
            &naming,
        );
        assert!(actions[0]
            .1
            .iter()
            .any(|step| matches!(step, shared::Step::Repair)));
        assert!(!root.path().join(&path).exists());
        fs::write(&copy, b"complete").unwrap();
        shared::tidy(
            &mut files::Shared { folder: &mut disk },
            shared::Area::Blobs,
            &naming,
        );
        assert_eq!(fs::read(root.path().join(&path)).unwrap(), b"complete");
        assert!(!copy.exists());
    }
}
