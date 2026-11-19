use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, Metadata, OpenOptions};
use marketplace_artifacts::{hash_stream, invalid, parse_json};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::{self, Read};

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 32_768;
const MAX_DIRECTORIES: usize = 32_768;
const MAX_DEPTH: usize = 64;
const MAX_PATH_BYTES: usize = 4095;
const MAX_CATALOG_ENTRIES: usize = 1000;
const IMMUTABLE_DIRECTORIES: [&str; 3] = ["keys", "releases", "deliverables"];
const CATALOG_FILES: [&str; 2] = ["catalog.json", "catalog.json.asc"];

fn main() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let command = args.next();
    let verify = match (command.as_deref(), args.next()) {
        (Some(command), None) if command == OsStr::new("admit") => false,
        (Some(command), None) if command == OsStr::new("verify-immutable") => true,
        _ => {
            return Err(invalid(
                "Usage: package-mirror-verifier admit|verify-immutable",
            ));
        }
    };

    let workspace = Dir::open_ambient_dir(".", ambient_authority())?;
    let checkout = workspace.open_dir_nofollow("source")?;
    let public = checkout.open_dir_nofollow("public")?;
    let mut inventory = Inventory::default();
    inventory.scan(&public, "", 0, false)?;

    if verify {
        verify_immutable(&public, inventory.immutable_files)?;
    }
    Ok(())
}

#[derive(Default)]
struct Inventory {
    file_count: usize,
    directory_count: usize,
    immutable_files: BTreeSet<String>,
}

impl Inventory {
    fn scan(&mut self, dir: &Dir, prefix: &str, depth: usize, immutable: bool) -> io::Result<()> {
        for entry in dir.entries()? {
            let name = entry?.file_name();
            let name = name
                .to_str()
                .filter(|name| safe_name(name))
                .ok_or_else(|| invalid("Unsafe public path name"))?;
            let path = format!("{prefix}{name}");
            if path.len() > MAX_PATH_BYTES {
                return Err(invalid("Public path exceeds the length limit"));
            }
            let info = dir.symlink_metadata(name)?;
            let immutable_directory = depth == 0 && IMMUTABLE_DIRECTORIES.contains(&name);
            if info.is_dir() {
                self.directory_count += 1;
                if self.directory_count > MAX_DIRECTORIES || depth >= MAX_DEPTH {
                    return Err(invalid("Public snapshot exceeds the directory limits"));
                }
                let child = dir.open_dir_nofollow(name)?;
                self.scan(
                    &child,
                    &format!("{path}/"),
                    depth + 1,
                    immutable || immutable_directory,
                )?;
                continue;
            }

            if immutable_directory {
                return Err(invalid("Expected an immutable repository directory"));
            }
            check_file(&info, &path)?;
            self.file_count += 1;
            if self.file_count > MAX_FILES {
                return Err(invalid("Public snapshot exceeds the file count limit"));
            }
            if immutable || (depth == 0 && CATALOG_FILES.contains(&name)) {
                self.immutable_files.insert(path);
            }
        }
        Ok(())
    }
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn check_file(info: &Metadata, path: &str) -> io::Result<()> {
    #[cfg(unix)]
    let executable = {
        use cap_std::fs::MetadataExt;
        info.mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;

    if !info.is_file() || info.nlink() != 1 || executable {
        return Err(invalid(format!(
            "Expected ordinary nonexecutable data at {path}"
        )));
    }
    if info.len() > MAX_FILE_BYTES {
        return Err(invalid(format!(
            "Public file exceeds the byte limit at {path}"
        )));
    }
    Ok(())
}

fn unchanged(previous: &Metadata, current: &Metadata, path: &str) -> io::Result<()> {
    check_file(current, path)?;
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        if (previous.ctime(), previous.ctime_nsec()) != (current.ctime(), current.ctime_nsec()) {
            return Err(invalid(format!("Public file changed while reading {path}")));
        }
    }
    if previous.dev() != current.dev()
        || previous.ino() != current.ino()
        || previous.len() != current.len()
        || previous.modified()? != current.modified()?
    {
        return Err(invalid(format!("Public file changed while reading {path}")));
    }
    Ok(())
}

fn open_file(root: &Dir, path: &str) -> io::Result<(File, Metadata)> {
    // Each caller uses a fixed name or one from the admitted inventory.
    let mut parent = root.try_clone()?;
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    if !directory.is_empty() {
        for component in directory.split('/') {
            parent = parent.open_dir_nofollow(component)?;
        }
    }
    let info = parent.symlink_metadata(name)?;
    check_file(&info, path)?;
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent.open_with(name, &options)?;
    unchanged(&info, &file.metadata()?, path)?;
    Ok((file, info))
}

fn read_json(root: &Dir, path: &str) -> io::Result<Vec<u8>> {
    let (mut file, info) = open_file(root, path)?;
    let mut bytes = Vec::new();
    (&mut file).take(info.len() + 1).read_to_end(&mut bytes)?;
    unchanged(&info, &file.metadata()?, path)?;
    if bytes.len() as u64 != info.len() {
        return Err(invalid(format!(
            "Public file length changed while reading {path}"
        )));
    }
    Ok(bytes)
}

fn verify_immutable(root: &Dir, mut expected: BTreeSet<String>) -> io::Result<()> {
    if !CATALOG_FILES.iter().all(|name| expected.contains(*name)) {
        return Err(invalid("Missing signed catalog files"));
    }
    let manifest = parse_json(&read_json(root, "immutable-files.json")?)?;
    let entries = manifest
        .get("files")
        .and_then(|value| value.as_array())
        .filter(|files| (1..=MAX_FILES).contains(&files.len()) && files.len() == expected.len())
        .ok_or_else(|| invalid("Incomplete immutable manifest"))?;
    if manifest
        .get("schemaVersion")
        .and_then(|value| value.as_u64())
        != Some(1)
    {
        return Err(invalid("Unsupported immutable manifest"));
    }

    let mut catalog_bytes = Vec::new();
    let mut sink = io::sink();
    for entry in entries {
        let path = entry
            .get("file")
            .and_then(|value| value.as_str())
            .filter(|path| expected.remove(*path))
            .ok_or_else(|| invalid("Unknown or duplicate immutable file"))?;
        let (mut source, info) = open_file(root, path)?;
        if entry.get("bytes").and_then(|value| value.as_u64()) != Some(info.len()) {
            return Err(invalid(format!("Immutable file length mismatch at {path}")));
        }
        let target: &mut dyn io::Write = if path == "catalog.json" {
            &mut catalog_bytes
        } else {
            &mut sink
        };
        let identity = hash_stream(&mut source, target, info.len())?;
        unchanged(&info, &source.metadata()?, path)?;
        if identity.size_bytes != info.len()
            || entry.get("sha256").and_then(|value| value.as_str()) != Some(&identity.sha256)
        {
            return Err(invalid(format!(
                "Immutable file checksum mismatch at {path}"
            )));
        }
    }

    let catalog = parse_json(&catalog_bytes)?;
    if !catalog
        .as_array()
        .is_some_and(|entries| (1..=MAX_CATALOG_ENTRIES).contains(&entries.len()))
    {
        return Err(invalid("Invalid signed catalog"));
    }
    Ok(())
}
