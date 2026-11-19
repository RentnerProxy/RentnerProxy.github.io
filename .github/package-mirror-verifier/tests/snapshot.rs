use marketplace_artifacts::digest;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

struct Snapshot {
    workspace: TempDir,
    public: PathBuf,
}

const IMMUTABLE: [&str; 5] = [
    "catalog.json",
    "catalog.json.asc",
    "keys/pinned.asc",
    "releases/stable/v1/guide.json",
    "deliverables/stable/v1/package.deb",
];

impl Snapshot {
    fn new() -> Self {
        let workspace = tempfile::tempdir().unwrap();
        let public = workspace.path().join("source/public");
        let snapshot = Self { workspace, public };
        for (path, data) in [
            ("catalog.json", r#"[{"version":"1.0.0"}]"#),
            ("catalog.json.asc", "signature fixture"),
            ("keys/pinned.asc", "key fixture"),
            ("releases/stable/v1/guide.json", "{}"),
            ("deliverables/stable/v1/package.deb", "package"),
            ("apt/dists/stable/InRelease", "mutable index fixture"),
            (
                "rpm/stable/x86_64/repodata/repomd.xml",
                "mutable index fixture",
            ),
            ("other/readme.txt", "other public file fixture"),
            ("immutable-files.json.asc", "signature fixture"),
        ] {
            snapshot.write(path, data);
        }
        snapshot.manifest(&IMMUTABLE);
        snapshot
    }

    fn write(&self, path: &str, data: impl AsRef<[u8]>) {
        let target = self.public.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, data).unwrap();
    }

    fn manifest(&self, paths: &[&str]) {
        let mut entries = Vec::new();
        for path in paths {
            let data = fs::read(self.public.join(path)).unwrap();
            entries.push(format!(
                r#"{{"file":"{path}","bytes":{},"sha256":"{}"}}"#,
                data.len(),
                digest(&data),
            ));
        }
        self.write(
            "immutable-files.json",
            format!(r#"{{"schemaVersion":1,"files":[{}]}}"#, entries.join(",")),
        );
    }

    fn assert_result(&self, command: &str, error: Option<&str>) {
        assert_result(self.workspace.path(), command, error);
    }
}

fn assert_result(workspace: &Path, command: &str, error: Option<&str>) {
    let output = Command::new(env!("CARGO_BIN_EXE_package-mirror-verifier"))
        .arg(command)
        .current_dir(workspace)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.success(), error.is_none(), "{stderr}");
    if let Some(error) = error {
        assert!(stderr.contains(error), "expected {error:?} in {stderr:?}");
    }
}

#[test]
fn accepts_complete_manifest_and_skips_mutable_indexes() {
    let snapshot = Snapshot::new();
    snapshot.assert_result("admit", None);
    snapshot.assert_result("verify-immutable", None);

    let mut reversed = IMMUTABLE;
    reversed.reverse();
    snapshot.manifest(&reversed);
    snapshot.write("apt/dists/stable/InRelease", "renewed independently");
    snapshot.assert_result("verify-immutable", None);
}

#[test]
fn checks_manifest_coverage_and_rejects_unknown_and_duplicate_paths() {
    let snapshot = Snapshot::new();
    snapshot.write("deliverables/stable/v1/extra.deb", "unlisted file");
    snapshot.assert_result("verify-immutable", Some("Incomplete immutable manifest"));
    fs::remove_file(snapshot.public.join("deliverables/stable/v1/extra.deb")).unwrap();

    let mut entries = IMMUTABLE;
    entries[4] = entries[0];
    snapshot.manifest(&entries);
    snapshot.assert_result(
        "verify-immutable",
        Some("Unknown or duplicate immutable file"),
    );

    for unknown in ["apt/dists/stable/InRelease", "keys/../catalog.json"] {
        entries[4] = unknown;
        snapshot.manifest(&entries);
        snapshot.assert_result(
            "verify-immutable",
            Some("Unknown or duplicate immutable file"),
        );
    }
}

#[test]
fn checks_both_size_and_checksum_and_requires_catalog_signature() {
    let snapshot = Snapshot::new();
    snapshot.write("deliverables/stable/v1/package.deb", "short");
    snapshot.assert_result("verify-immutable", Some("Immutable file length mismatch"));
    snapshot.write("deliverables/stable/v1/package.deb", "changed");
    snapshot.assert_result("verify-immutable", Some("Immutable file checksum mismatch"));
    fs::remove_file(snapshot.public.join("catalog.json.asc")).unwrap();
    snapshot.assert_result("verify-immutable", Some("Missing signed catalog files"));
}

#[test]
fn rejects_malformed_or_unsupported_metadata_and_invalid_catalog_size() {
    let snapshot = Snapshot::new();
    snapshot.write(
        "immutable-files.json",
        r#"{"schemaVersion":1,"files":false}"#,
    );
    snapshot.assert_result("verify-immutable", Some("Incomplete immutable manifest"));
    snapshot.manifest(&IMMUTABLE);
    let manifest = fs::read_to_string(snapshot.public.join("immutable-files.json")).unwrap();
    snapshot.write(
        "immutable-files.json",
        manifest.replace(r#""schemaVersion":1"#, r#""schemaVersion":2"#),
    );
    snapshot.assert_result("verify-immutable", Some("Unsupported immutable manifest"));
    snapshot.write(
        "immutable-files.json",
        manifest.replace(
            r#""schemaVersion":1"#,
            r#""schemaVersion":1,"schemaVersion":1"#,
        ),
    );
    snapshot.assert_result("verify-immutable", Some("Duplicate JSON member"));

    for catalog in [
        "[]".into(),
        "{}".into(),
        format!("[{}null]", "null,".repeat(1000)),
    ] {
        snapshot.write("catalog.json", catalog);
        snapshot.manifest(&IMMUTABLE);
        snapshot.assert_result("verify-immutable", Some("Invalid signed catalog"));
    }
    snapshot.write("catalog.json", "[");
    snapshot.manifest(&IMMUTABLE);
    snapshot.assert_result("verify-immutable", Some("Invalid or ambiguous JSON"));
}

#[test]
fn rejects_unsafe_names_oversized_files_and_deep_directories() {
    let snapshot = Snapshot::new();
    for file in [".hidden", "a space", "pünktchen"] {
        snapshot.write(file, "");
        snapshot.assert_result("admit", Some("Unsafe public path name"));
        fs::remove_file(snapshot.public.join(file)).unwrap();
    }
    let large = snapshot.public.join("large");
    fs::File::create(&large)
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    snapshot.assert_result("admit", Some("Public file exceeds the byte limit"));
    fs::remove_file(large).unwrap();

    fs::create_dir_all(snapshot.public.join("d/".repeat(65))).unwrap();
    snapshot.assert_result(
        "admit",
        Some("Public snapshot exceeds the directory limits"),
    );
}

#[test]
fn rejects_hard_links() {
    let snapshot = Snapshot::new();
    fs::hard_link(
        snapshot.public.join("catalog.json"),
        snapshot.public.join("alias.json"),
    )
    .unwrap();
    snapshot.assert_result("admit", Some("Expected ordinary nonexecutable data"));
    snapshot.assert_result(
        "verify-immutable",
        Some("Expected ordinary nonexecutable data"),
    );
}

#[cfg(unix)]
#[test]
fn rejects_executable_files_and_symlinks_at_every_level() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let snapshot = Snapshot::new();
    let file = snapshot.public.join("mode");
    fs::write(&file, "").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
    snapshot.assert_result("admit", Some("Expected ordinary nonexecutable data"));
    fs::remove_file(&file).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let outside_file = outside.path().join("regular.txt");
    fs::write(&outside_file, "").unwrap();

    for target in [&outside_file, &outside.path().to_path_buf()] {
        symlink(target, &file).unwrap();
        snapshot.assert_result("admit", Some("Expected ordinary nonexecutable data"));
        snapshot.assert_result(
            "verify-immutable",
            Some("Expected ordinary nonexecutable data"),
        );
        fs::remove_file(&file).unwrap();
    }

    fs::rename(&snapshot.public, snapshot.public.with_file_name("renamed")).unwrap();
    symlink(snapshot.public.with_file_name("renamed"), &snapshot.public).unwrap();
    snapshot.assert_result("admit", Some(""));
    fs::remove_file(&snapshot.public).unwrap();
    let source = snapshot.public.parent().unwrap();
    fs::rename(source, source.with_file_name("other")).unwrap();
    symlink(source.with_file_name("other"), source).unwrap();
    snapshot.assert_result("admit", Some(""));
}
