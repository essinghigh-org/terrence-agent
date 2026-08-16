use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tar::{Archive, Builder, EntryType, Header};
use walkdir::WalkDir;

pub const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;

pub fn extract_tar_gz(bytes: &[u8], destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("create extraction directory {}", destination.display()))?;
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut extracted_bytes = 0_u64;

    for entry in archive.entries().context("read tar archive entries")? {
        let mut entry = entry.context("read tar archive entry")?;
        let relative = validate_entry_path(&entry.path().context("read tar entry path")?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let entry_type = entry.header().entry_type();
        let output = destination.join(&relative);
        if entry_type == EntryType::Directory {
            fs::create_dir_all(&output)
                .with_context(|| format!("create directory {}", output.display()))?;
            continue;
        }
        if entry_type != EntryType::Regular {
            bail!(
                "archive contains unsupported entry type at {}",
                relative.display()
            );
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent directory {}", parent.display()))?;
        }
        let mut file = File::create(&output)
            .with_context(|| format!("create extracted file {}", output.display()))?;
        let written = copy_limited(&mut entry, &mut file, MAX_EXTRACTED_BYTES - extracted_bytes)
            .with_context(|| format!("extract {}", relative.display()))?;
        extracted_bytes = extracted_bytes.saturating_add(written);
        if let Ok(mode) = entry.header().mode() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&output, fs::Permissions::from_mode(mode & 0o777))?;
            }
        }
    }
    Ok(())
}

pub fn flatten_single_directory(destination: &Path) -> Result<()> {
    let entries = fs::read_dir(destination)
        .with_context(|| format!("read extracted directory {}", destination.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    if entries.len() != 1 || !entries[0].file_type()?.is_dir() {
        return Ok(());
    }
    let inner = entries[0].path();
    for entry in fs::read_dir(&inner)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if target.exists() {
            bail!("flattening archive would overwrite {}", target.display());
        }
        fs::rename(entry.path(), target)?;
    }
    fs::remove_dir(inner)?;
    Ok(())
}

pub fn pack_tar_gz(source: &Path) -> Result<Vec<u8>> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry.context("walk snapshot directory")?;
        let path = entry.path();
        if path == source {
            continue;
        }
        let relative = path
            .strip_prefix(source)
            .context("snapshot path is outside its source directory")?;
        if is_excluded(relative) {
            if entry.file_type().is_dir() {
                continue;
            }
            continue;
        }
        if entry.file_type().is_symlink() {
            bail!(
                "snapshot contains unsupported symlink {}",
                relative.display()
            );
        }
        if entry.file_type().is_dir() {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Directory);
            header.set_mode(0o700);
            header.set_size(0);
            header.set_cksum();
            builder.append_data(&mut header, relative, io::empty())?;
        } else if entry.file_type().is_file() {
            builder.append_path_with_name(path, relative)?;
        } else {
            bail!("snapshot contains unsupported file {}", relative.display());
        }
    }
    let encoder = builder.into_inner().context("finish tar archive")?;
    let bytes = encoder.finish().context("finish gzip archive")?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        bail!("filesystem snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes");
    }
    Ok(bytes)
}

fn is_excluded(path: &Path) -> bool {
    path.components().next().is_some_and(|component| {
        matches!(component, Component::Normal(name) if name == "secrets" || name == "tmp")
    })
}

fn validate_entry_path(path: &Path) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => clean.push(value),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                bail!("archive contains unsafe path {}", path.display())
            }
        }
    }
    Ok(clean)
}

fn copy_limited(reader: &mut impl Read, writer: &mut impl Write, remaining: u64) -> Result<u64> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        if total + read as u64 > remaining {
            bail!("archive expands beyond the extraction limit");
        }
        writer.write_all(&buffer[..read])?;
        total += read as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn rejects_traversal() {
        assert!(validate_entry_path(Path::new("../escape")).is_err());
        assert!(validate_entry_path(Path::new("/escape")).is_err());
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
}
