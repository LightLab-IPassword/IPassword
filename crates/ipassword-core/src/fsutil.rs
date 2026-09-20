use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

/// Crash-safe write: write to a temp file in the same directory, flush it to
/// disk, then rename over the target. A crash leaves either the old file or
/// the new one, never a half-written mix. (On Windows, `fs::rename` replaces
/// an existing destination.)
pub(crate) fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;

    let mut suffix = [0u8; 4];
    getrandom::getrandom(&mut suffix)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{}.{}.tmp", file_name, hex::encode(suffix)));

    let result = (|| -> io::Result<()> {
        let mut f = File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_replaces_without_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("sub").join("f.bin");
        write_atomic(&target, b"one").unwrap();
        write_atomic(&target, b"two").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        let leftovers = fs::read_dir(target.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1, "temp files must not be left behind");
    }
}
