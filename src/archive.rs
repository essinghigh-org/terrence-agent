use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tar::{Archive, Builder, EntryType, Header};
use walkdir::WalkDir;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 100_000;
pub const MAX_ARCHIVE_DIRECTORIES: usize = 50_000;
pub const MAX_ARCHIVE_PATH_DEPTH: usize = 64;
pub const MAX_ARCHIVE_PATH_BYTES: usize = 4 * 1024;
pub const MAX_ARCHIVE_FILE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_SNAPSHOT_SOURCE_BYTES: u64 = MAX_EXTRACTED_BYTES;

const MAX_GZIP_EXPANSION_RATIO: u64 = 1_000;

/// Extract a gzip-compressed tar archive held in memory.
///
/// New callers should prefer [`extract_tar_gz_file`] so the compressed archive
/// is never materialized in the process heap.
pub fn extract_tar_gz(bytes: &[u8], destination: &Path) -> Result<()> {
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES as u64 {
        bail!(
            "compressed archive exceeds the {} byte limit",
            MAX_SNAPSHOT_BYTES
        );
    }
    extract_tar_gz_reader(Cursor::new(bytes), destination)
}

/// Extract a gzip-compressed tar archive directly from a file.
#[allow(dead_code)]
pub fn extract_tar_gz_file(archive_path: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::metadata(archive_path)
        .with_context(|| format!("stat archive {}", archive_path.display()))?;
    if !metadata.is_file() {
        bail!(
            "archive path is not a regular file: {}",
            archive_path.display()
        );
    }
    if metadata.len() > MAX_SNAPSHOT_BYTES as u64 {
        bail!(
            "compressed archive exceeds the {} byte limit",
            MAX_SNAPSHOT_BYTES
        );
    }
    let file = File::open(archive_path)
        .with_context(|| format!("open archive {}", archive_path.display()))?;
    extract_tar_gz_reader(file, destination)
}

fn extract_tar_gz_reader<R: Read>(reader: R, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("create extraction directory {}", destination.display()))?;
    let destination = fs::canonicalize(destination).with_context(|| {
        format!(
            "canonicalize extraction directory {}",
            destination.display()
        )
    })?;
    set_private_directory(&destination)?;

    let compressed = CountingReader::new(reader);
    let decoder = GzDecoder::new(compressed);
    let mut decoded = CountingReader::new(decoder);
    let mut archive = Archive::new(&mut decoded);
    let mut state = ExtractionState::new(destination);

    for entry in archive.entries().context("read tar archive entries")? {
        let mut entry = entry.context("read tar archive entry")?;
        state.entries += 1;
        if state.entries > MAX_ARCHIVE_ENTRIES {
            bail!("archive contains more than {MAX_ARCHIVE_ENTRIES} entries");
        }

        let entry_type = entry.header().entry_type();
        let relative = validate_entry_path(&entry.path().context("read tar entry path")?)?;
        if matches!(
            entry_type,
            EntryType::XHeader
                | EntryType::XGlobalHeader
                | EntryType::GNULongName
                | EntryType::GNULongLink
        ) {
            continue;
        }

        if relative.as_os_str().is_empty() {
            continue;
        }
        let output = state.output_path(&relative)?;
        if entry_type == EntryType::Directory {
            state.ensure_directory(&relative, &output)?;
            if !state.seen_entries.insert(relative) {
                bail!("archive contains duplicate path {}", output.display());
            }
            continue;
        }
        if entry_type != EntryType::Regular {
            bail!(
                "archive contains unsupported entry type at {}",
                relative.display()
            );
        }

        let size = entry.header().size().context("read tar entry size")?;
        if size > MAX_ARCHIVE_FILE_BYTES {
            bail!(
                "archive entry {} exceeds the {} byte file limit",
                relative.display(),
                MAX_ARCHIVE_FILE_BYTES
            );
        }
        if state.extracted_bytes.saturating_add(size) > MAX_EXTRACTED_BYTES {
            bail!("archive expands beyond the extraction limit");
        }
        state.ensure_parents(&relative)?;
        if !state.seen_entries.insert(relative.clone()) {
            bail!("archive contains duplicate path {}", output.display());
        }
        if fs::symlink_metadata(&output).is_ok() {
            bail!(
                "archive entry collides with existing path {}",
                output.display()
            );
        }
        let mode = entry.header().mode().unwrap_or(0);
        let mut file = private_file(&output, mode & 0o111 != 0)
            .with_context(|| format!("create extracted file {}", output.display()))?;
        let written = copy_limited(
            &mut entry,
            &mut file,
            MAX_EXTRACTED_BYTES - state.extracted_bytes,
        )
        .with_context(|| format!("extract {}", relative.display()))?;
        state.extracted_bytes = state.extracted_bytes.saturating_add(written);
        file.sync_all()
            .with_context(|| format!("sync extracted file {}", output.display()))?;
        if mode & 0o111 != 0 {
            set_private_file(&output, true)?;
        }
    }
    #[allow(clippy::drop_non_drop)]
    drop(archive);

    let decompressed_bytes = decoded.bytes_read;
    let compressed_bytes = decoded.inner.get_ref().bytes_read;
    if compressed_bytes > 0
        && decompressed_bytes > compressed_bytes.saturating_mul(MAX_GZIP_EXPANSION_RATIO)
    {
        bail!("gzip archive expands beyond the {MAX_GZIP_EXPANSION_RATIO}:1 ratio");
    }
    Ok(())
}

pub fn flatten_single_directory(destination: &Path) -> Result<()> {
    let destination = fs::canonicalize(destination)
        .with_context(|| format!("canonicalize extracted directory {}", destination.display()))?;
    let mut entries = fs::read_dir(&destination)
        .with_context(|| format!("read extracted directory {}", destination.display()))?;
    let Some(inner_entry) = entries.next().transpose()? else {
        return Ok(());
    };
    if entries.next().transpose()?.is_some() || !inner_entry.file_type()?.is_dir() {
        return Ok(());
    }
    let inner = inner_entry.path();
    for entry in fs::read_dir(&inner)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if !target.starts_with(&destination) {
            bail!("flattened archive path escapes destination");
        }
        if fs::symlink_metadata(&target).is_ok() {
            bail!("flattening archive would overwrite {}", target.display());
        }
        fs::rename(entry.path(), target)?;
    }
    fs::remove_dir(inner)?;
    Ok(())
}

/// Pack a snapshot into a bounded in-memory buffer.
pub fn pack_tar_gz(source: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pack_tar_gz_into(source, &mut bytes)?;
    Ok(bytes)
}

/// Pack a snapshot directly to a private file, enforcing the same output cap
/// as [`pack_tar_gz`].
#[allow(dead_code)]
pub fn pack_tar_gz_file(source: &Path, archive_path: &Path) -> Result<()> {
    let source_root = fs::canonicalize(source)
        .with_context(|| format!("canonicalize snapshot directory {}", source.display()))?;
    let output_parent = archive_path.parent().unwrap_or_else(|| Path::new("."));
    let output_parent = fs::canonicalize(output_parent)
        .with_context(|| format!("canonicalize archive directory {}", output_parent.display()))?;
    let output_name = archive_path
        .file_name()
        .context("snapshot archive path has no file name")?;
    if output_parent.join(output_name).starts_with(&source_root) {
        bail!("snapshot archive must not be written inside its source directory");
    }
    let mut output = private_output_file(archive_path)?;
    let result = pack_tar_gz_into(source, &mut output);
    if let Err(error) = result {
        drop(output);
        let _ = fs::remove_file(archive_path);
        return Err(error);
    }
    if let Err(error) = output
        .sync_all()
        .with_context(|| format!("sync snapshot archive {}", archive_path.display()))
    {
        drop(output);
        let _ = fs::remove_file(archive_path);
        return Err(error);
    }
    Ok(())
}

fn pack_tar_gz_into<W: Write>(source: &Path, output: W) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("stat snapshot directory {}", source.display()))?;
    if !metadata.is_dir() {
        bail!("snapshot source is not a directory: {}", source.display());
    }

    let output = LimitedWriter::new(output, MAX_SNAPSHOT_BYTES as u64);
    let encoder = GzEncoder::new(output, Compression::default());
    let mut builder = Builder::new(encoder);
    let walker = WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.path() == source
                || entry
                    .path()
                    .strip_prefix(source)
                    .map(|relative| !is_excluded(relative))
                    .unwrap_or(false)
        });
    let mut entries = 0_usize;
    let mut directories = HashSet::new();
    let mut source_bytes = 0_u64;

    for entry in walker {
        let entry = entry.context("walk snapshot directory")?;
        let path = entry.path();
        if path == source {
            continue;
        }
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            bail!("snapshot contains more than {MAX_ARCHIVE_ENTRIES} entries");
        }
        let relative = path
            .strip_prefix(source)
            .context("snapshot path is outside its source directory")?;
        let relative = validate_entry_path(relative)?;
        if entry.file_type().is_symlink() {
            bail!(
                "snapshot contains unsupported symlink {}",
                relative.display()
            );
        }
        if entry.file_type().is_dir() {
            if directories.insert(relative.clone()) && directories.len() > MAX_ARCHIVE_DIRECTORIES {
                bail!("snapshot contains more than {MAX_ARCHIVE_DIRECTORIES} directories");
            }
            let mut header = normalized_header(EntryType::Directory, 0, 0o700);
            builder
                .append_data(&mut header, &relative, io::empty())
                .with_context(|| format!("pack snapshot directory {}", relative.display()))?;
        } else if entry.file_type().is_file() {
            let metadata = entry.metadata().context("read snapshot file metadata")?;
            if metadata.len() > MAX_ARCHIVE_FILE_BYTES {
                bail!(
                    "snapshot file {} exceeds the {} byte limit",
                    relative.display(),
                    MAX_ARCHIVE_FILE_BYTES
                );
            }
            source_bytes = source_bytes.saturating_add(metadata.len());
            if source_bytes > MAX_SNAPSHOT_SOURCE_BYTES {
                bail!(
                    "snapshot source exceeds the {} byte limit",
                    MAX_SNAPSHOT_SOURCE_BYTES
                );
            }
            let mode = file_mode(&metadata);
            let mut header = normalized_header(EntryType::Regular, metadata.len(), mode);
            let mut file = File::open(path)
                .with_context(|| format!("open snapshot file {}", path.display()))?;
            builder
                .append_data(&mut header, &relative, &mut file)
                .with_context(|| format!("pack snapshot file {}", relative.display()))?;
        } else {
            bail!("snapshot contains unsupported file {}", relative.display());
        }
    }
    let encoder = builder.into_inner().context("finish tar archive")?;
    encoder.finish().context("finish gzip archive").map(|_| ())
}

fn normalized_header(entry_type: EntryType, size: u64, mode: u32) -> Header {
    let mut header = Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    header
}

fn is_excluded(path: &Path) -> bool {
    path.components().next().is_some_and(|component| {
        matches!(component, Component::Normal(name) if name == "secrets" || name == "tmp")
    })
}

fn validate_entry_path(path: &Path) -> Result<PathBuf> {
    if path_byte_len(path) > MAX_ARCHIVE_PATH_BYTES {
        bail!("archive path exceeds the {MAX_ARCHIVE_PATH_BYTES} byte limit");
    }
    let mut clean = PathBuf::new();
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                depth += 1;
                if depth > MAX_ARCHIVE_PATH_DEPTH {
                    bail!("archive path exceeds the {MAX_ARCHIVE_PATH_DEPTH} component limit");
                }
                clean.push(value);
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                bail!("archive contains unsafe path {}", path.display())
            }
        }
    }
    Ok(clean)
}

fn path_byte_len(path: &Path) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().len()
    }
    #[cfg(not(unix))]
    {
        path.to_string_lossy().len()
    }
}

fn copy_limited(reader: &mut impl Read, writer: &mut impl Write, remaining: u64) -> Result<u64> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        if total.saturating_add(read as u64) > remaining {
            bail!("archive expands beyond the extraction limit");
        }
        writer.write_all(&buffer[..read])?;
        total += read as u64;
    }
}

struct ExtractionState {
    destination: PathBuf,
    entries: usize,
    extracted_bytes: u64,
    directories: HashSet<PathBuf>,
    seen_entries: HashSet<PathBuf>,
}

impl ExtractionState {
    fn new(destination: PathBuf) -> Self {
        Self {
            destination,
            entries: 0,
            extracted_bytes: 0,
            directories: HashSet::new(),
            seen_entries: HashSet::new(),
        }
    }

    fn output_path(&self, relative: &Path) -> Result<PathBuf> {
        let output = self.destination.join(relative);
        if !output.starts_with(&self.destination) {
            bail!("archive path escapes extraction destination");
        }
        Ok(output)
    }

    fn ensure_parents(&mut self, relative: &Path) -> Result<()> {
        let Some(parent) = relative.parent() else {
            return Ok(());
        };
        let mut current = PathBuf::new();
        for component in parent.components() {
            let Component::Normal(component) = component else {
                continue;
            };
            current.push(component);
            let output = self.output_path(&current)?;
            self.ensure_directory_path(&current, &output)?;
        }
        Ok(())
    }

    fn ensure_directory(&mut self, relative: &Path, output: &Path) -> Result<()> {
        self.ensure_parents(relative)?;
        self.ensure_directory_path(relative, output)
    }

    fn ensure_directory_path(&mut self, relative: &Path, output: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(output);
        match metadata {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("archive path traverses symlink {}", output.display())
            }
            Ok(metadata) if !metadata.is_dir() => {
                bail!("archive file/directory collision at {}", output.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(output)
                    .with_context(|| format!("create extracted directory {}", output.display()))?;
                set_private_directory(output)?;
            }
            Err(error) => return Err(error.into()),
        }
        if self.directories.insert(relative.to_owned())
            && self.directories.len() > MAX_ARCHIVE_DIRECTORIES
        {
            bail!("archive contains more than {MAX_ARCHIVE_DIRECTORIES} directories");
        }
        Ok(())
    }
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes_read = self.bytes_read.saturating_add(read as u64);
        Ok(read)
    }
}

struct LimitedWriter<W> {
    inner: W,
    limit: u64,
    bytes_written: u64,
}

impl<W> LimitedWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            bytes_written: 0,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes_written.saturating_add(buffer.len() as u64) > self.limit {
            return Err(io::Error::other(format!(
                "archive exceeds the {} byte limit",
                self.limit
            )));
        }
        let written = self.inner.write(buffer)?;
        self.bytes_written = self.bytes_written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[allow(dead_code)]
fn private_output_file(path: &Path) -> Result<File> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "snapshot archive path is not a regular file: {}",
                path.display()
            );
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("create snapshot archive {}", path.display()))?;
    set_private_file(path, false)?;
    Ok(file)
}

fn private_file(path: &Path, executable: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(if executable { 0o700 } else { 0o600 });
    options.open(path).map_err(Into::into)
}

fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn set_private_file(path: &Path, executable: bool) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable { 0o700 } else { 0o600 }),
    )?;
    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().mode() & 0o111 != 0 {
        0o700
    } else {
        0o600
    }
}

#[cfg(not(unix))]
fn file_mode(_metadata: &fs::Metadata) -> u32 {
    0o600
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_traversal_and_path_limits() {
        assert!(validate_entry_path(Path::new("../escape")).is_err());
        assert!(validate_entry_path(Path::new("/escape")).is_err());
        assert!(
            validate_entry_path(&PathBuf::from_iter(std::iter::repeat_n(
                "deep",
                MAX_ARCHIVE_PATH_DEPTH + 1
            ),))
            .is_err()
        );
    }

    #[test]
    fn extracts_and_flattens_git_style_archives() {
        let source = tempdir().unwrap();
        fs::create_dir_all(source.path().join("repo")).unwrap();
        fs::write(source.path().join("repo/main.tf"), b"resource {} ").unwrap();
        let archive = pack_tar_gz(source.path()).unwrap();
        let destination = tempdir().unwrap();
        extract_tar_gz(&archive, destination.path()).unwrap();
        flatten_single_directory(destination.path()).unwrap();
        assert!(destination.path().join("main.tf").exists());
        assert!(!destination.path().join("repo").exists());
    }

    #[test]
    fn handles_long_paths_with_tar_metadata() {
        let source = tempdir().unwrap();
        let long_name = format!("{}.tf", "a".repeat(140));
        fs::write(source.path().join(&long_name), b"resource {} ").unwrap();
        let archive = pack_tar_gz(source.path()).unwrap();
        let destination = tempdir().unwrap();
        extract_tar_gz(&archive, destination.path()).unwrap();
        assert_eq!(
            fs::read(destination.path().join(long_name)).unwrap(),
            b"resource {} "
        );
    }

    #[test]
    fn snapshots_exclude_credentials_and_tmp_files() {
        let source = tempdir().unwrap();
        fs::create_dir_all(source.path().join("secrets")).unwrap();
        fs::create_dir_all(source.path().join("tmp")).unwrap();
        fs::write(source.path().join("secrets/token"), b"secret").unwrap();
        fs::write(source.path().join("tmp/noise"), b"noise").unwrap();
        fs::write(source.path().join("tfplan"), b"plan").unwrap();
        let archive = pack_tar_gz(source.path()).unwrap();
        let destination = tempdir().unwrap();
        extract_tar_gz(&archive, destination.path()).unwrap();
        assert!(destination.path().join("tfplan").exists());
        assert!(!destination.path().join("secrets/token").exists());
        assert!(!destination.path().join("tmp/noise").exists());
    }

    #[test]
    fn snapshot_archives_are_deterministic() {
        let source = tempdir().unwrap();
        fs::create_dir_all(source.path().join("nested")).unwrap();
        fs::write(source.path().join("nested/file"), b"snapshot").unwrap();
        fs::write(source.path().join("root"), b"root").unwrap();
        assert_eq!(
            pack_tar_gz(source.path()).unwrap(),
            pack_tar_gz(source.path()).unwrap()
        );
    }

    #[test]
    fn rejects_duplicate_and_colliding_entries() {
        let destination = tempdir().unwrap();
        let mut bytes = Vec::new();
        {
            let encoder = GzEncoder::new(&mut bytes, Compression::default());
            let mut builder = Builder::new(encoder);
            let mut header = normalized_header(EntryType::Regular, 1, 0o600);
            builder.append_data(&mut header, "same", &b"a"[..]).unwrap();
            let mut duplicate = normalized_header(EntryType::Regular, 1, 0o600);
            builder
                .append_data(&mut duplicate, "same", &b"b"[..])
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }
        assert!(extract_tar_gz(&bytes, destination.path()).is_err());

        let destination = tempdir().unwrap();
        let mut bytes = Vec::new();
        {
            let encoder = GzEncoder::new(&mut bytes, Compression::default());
            let mut builder = Builder::new(encoder);
            let mut header = normalized_header(EntryType::Regular, 1, 0o600);
            builder.append_data(&mut header, "same", &b"a"[..]).unwrap();
            let mut child = normalized_header(EntryType::Regular, 1, 0o600);
            builder
                .append_data(&mut child, "same/child", &b"b"[..])
                .unwrap();
            builder.into_inner().unwrap().finish().unwrap();
        }
        assert!(extract_tar_gz(&bytes, destination.path()).is_err());
    }

    #[test]
    fn extraction_uses_private_permissions_and_rejects_symlink_escape() {
        let source = tempdir().unwrap();
        fs::write(source.path().join("file"), b"secret").unwrap();
        let archive = pack_tar_gz(source.path()).unwrap();
        let destination = tempdir().unwrap();
        extract_tar_gz(&archive, destination.path()).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(destination.path().join("file"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        #[cfg(unix)]
        {
            let destination = tempdir().unwrap();
            let outside = tempdir().unwrap();
            std::os::unix::fs::symlink(outside.path(), destination.path().join("escape")).unwrap();
            let mut bytes = Vec::new();
            {
                let encoder = GzEncoder::new(&mut bytes, Compression::default());
                let mut builder = Builder::new(encoder);
                let mut header = normalized_header(EntryType::Regular, 1, 0o600);
                builder
                    .append_data(&mut header, "escape/file", &b"x"[..])
                    .unwrap();
                builder.into_inner().unwrap().finish().unwrap();
            }
            assert!(extract_tar_gz(&bytes, destination.path()).is_err());
            assert!(!outside.path().join("file").exists());
        }
    }

    #[test]
    fn file_apis_stream_and_keep_private_modes() {
        let source = tempdir().unwrap();
        fs::write(source.path().join("file"), b"snapshot").unwrap();
        let archive_dir = tempdir().unwrap();
        let archive = archive_dir.path().join("snapshot.tgz");
        pack_tar_gz_file(source.path(), &archive).unwrap();
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let destination = tempdir().unwrap();
        extract_tar_gz_file(&archive, destination.path()).unwrap();
        assert_eq!(
            fs::read(destination.path().join("file")).unwrap(),
            b"snapshot"
        );
    }
}
