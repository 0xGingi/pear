use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use pear_core::sync::sync_cycle;
use tempfile::tempdir;

#[test]
fn one_shot_sync_converges_target() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::create_dir_all(a.join("src")).unwrap();
    fs::write(a.join("src/main.rs"), b"fn main() {}\n").unwrap();
    fs::write(a.join("README.md"), b"# demo\n").unwrap();
    fs::write(a.join(".env"), b"SECRET=1\n").unwrap();
    fs::write(a.join(".gitignore"), b"*.log\n").unwrap();
    fs::write(a.join("debug.log"), b"noise\n").unwrap();
    fs::create_dir_all(a.join("node_modules/pkg")).unwrap();
    fs::write(a.join("node_modules/pkg/index.js"), b"m\n").unwrap();
    fs::create_dir_all(a.join(".git/refs/heads")).unwrap();
    fs::write(a.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        a.join(".git/refs/heads/main"),
        b"0123456789abcdef0123456789abcdef01234567\n",
    )
    .unwrap();
    fs::write(a.join("tool.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    make_executable(&a.join("tool.sh"));

    let r1 = sync_cycle(a, b).unwrap();
    assert!(r1.chunks_uploaded > 0);
    assert!(b.join(".pear/manifest.json").exists());
    assert!(b.join(".pear/store/chunks").is_dir());

    assert_trees_equal(a, b);
    assert!(
        !b.join("debug.log").exists(),
        "gitignored file must not sync"
    );
    assert!(
        !b.join("node_modules").exists(),
        "node_modules must not sync"
    );
    assert_eq!(
        fs::read(b.join(".git/HEAD")).unwrap(),
        b"ref: refs/heads/main\n"
    );
    assert!(
        mode_of(&b.join("tool.sh")) & 0o111 != 0,
        "must stay executable"
    );

    // Second cycle: modify one file, delete another, add a third.
    fs::write(a.join("src/main.rs"), b"fn main() { println!(\"v2\"); }\n").unwrap();
    fs::remove_file(a.join("README.md")).unwrap();
    fs::write(a.join("newfile.txt"), b"fresh\n").unwrap();

    let r2 = sync_cycle(a, b).unwrap();
    assert!(r2.written.contains(&"src/main.rs".to_string()));
    assert!(r2.written.contains(&"newfile.txt".to_string()));
    assert!(r2.deleted.contains(&"README.md".to_string()));

    assert_trees_equal(a, b);
    assert_eq!(
        fs::read(b.join(".git/refs/heads/main")).unwrap(),
        b"0123456789abcdef0123456789abcdef01234567\n",
        ".git content must survive incremental syncs"
    );
}

/// The target must contain exactly the files the scan rules select from the
/// source (nothing more, nothing less), byte- and mode-identical.
fn assert_trees_equal(a: &Path, b: &Path) {
    let scanned = pear_core::scan::scan(a).unwrap().files;
    let mut expected: BTreeMap<String, (Vec<u8>, u32)> = BTreeMap::new();
    for f in &scanned {
        expected.insert(
            f.rel_path.clone(),
            (fs::read(a.join(&f.rel_path)).unwrap(), f.mode & 0o7777),
        );
    }

    let mut actual: BTreeMap<String, (Vec<u8>, u32)> = BTreeMap::new();
    let mut stack = vec![b.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(b).unwrap();
            if rel
                .components()
                .next()
                .is_some_and(|c| c.as_os_str() == ".pear")
            {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                let rel = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/");
                actual.insert(rel, (fs::read(&path).unwrap(), mode_of(&path) & 0o7777));
            }
        }
    }

    let expected_keys: BTreeSet<_> = expected.keys().collect();
    let actual_keys: BTreeSet<_> = actual.keys().collect();
    assert_eq!(actual_keys, expected_keys, "file sets differ");
    for (path, (bytes, mode)) in &expected {
        let (actual_bytes, actual_mode) = &actual[path];
        assert_eq!(actual_bytes, bytes, "content mismatch: {path}");
        assert_eq!(actual_mode, mode, "mode mismatch: {path}");
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).unwrap().mode()
}

#[cfg(not(unix))]
fn mode_of(_path: &Path) -> u32 {
    0o644
}

#[test]
fn resync_into_fresh_target_converges() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("one.txt"), b"one\n").unwrap();
    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("one.txt")).unwrap(), b"one\n");

    // Wipe the mirror completely; the source-side chunk cache must not
    // skip uploading chunks the fresh store lacks.
    fs::remove_dir_all(b).unwrap();
    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("one.txt")).unwrap(), b"one\n");
}

#[test]
fn same_size_same_mtime_edit_still_syncs() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("data.txt"), b"aaaa\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Same-length edit with the mtime forced back to its previous value —
    // what a coarse-timestamp filesystem makes an edit look like. The cache
    // must distrust the unsettled mtime and re-chunk.
    let recorded = fs::metadata(a.join("data.txt"))
        .unwrap()
        .modified()
        .unwrap();
    fs::write(a.join("data.txt"), b"bbbb\n").unwrap();
    filetime::set_file_mtime(a.join("data.txt"), recorded.into()).unwrap();

    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("data.txt")).unwrap(), b"bbbb\n");
}

#[test]
fn manifest_with_traversal_path_is_rejected() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let outside_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("ok.txt"), b"ok\n").unwrap();
    // A victim file outside the target, and a planted target-side manifest
    // that claims it should be deleted.
    let victim = outside_dir.path().join("victim.txt");
    fs::write(&victim, b"precious\n").unwrap();
    let rel_to_victim = format!(
        "../{}/victim.txt",
        outside_dir.path().file_name().unwrap().to_string_lossy()
    );

    let mut files = BTreeMap::new();
    files.insert(
        rel_to_victim,
        pear_core::manifest::FileEntry {
            size: 9,
            mode: 0o644,
            mtime_secs: 0,
            mtime_nanos: 0,
            chunks: vec![],
        },
    );
    let planted = pear_core::manifest::Manifest {
        version: 1,
        workspace_id: "planted".to_string(),
        scanned_at_secs: 0,
        files,
    };
    fs::create_dir_all(b.join(".pear")).unwrap();
    pear_core::manifest::write_atomic(&b.join(".pear/manifest.json"), &planted).unwrap();

    assert!(
        sync_cycle(a, b).is_err(),
        "a manifest with ../ paths must be rejected"
    );
    assert_eq!(fs::read(&victim).unwrap(), b"precious\n");
}

#[cfg(unix)]
#[test]
fn non_utf8_filename_is_skipped_not_fatal() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("good.txt"), b"good\n").unwrap();
    // Linux filenames are arbitrary bytes; a non-UTF-8 name must be
    // skipped with a warning, not poison the whole cycle. Some
    // filesystems (APFS on macOS) refuse to create such names at all,
    // in which case the scenario does not apply here.
    let bad_name = OsStr::from_bytes(b"bad-\xff-name.txt");
    if fs::write(a.join(bad_name), b"bad\n").is_err() {
        return;
    }

    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("good.txt")).unwrap(), b"good\n");
    assert!(!b.join(bad_name).exists());
}

#[cfg(unix)]
#[test]
fn unreadable_file_is_skipped_cycle_converges() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("locked.txt"), b"v1\n").unwrap();
    fs::write(a.join("other.txt"), b"one\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Persistently unreadable (write-only) and changed: the cycle must skip
    // the file with a warning, keep the mirror's last-good copy, and still
    // converge everything else.
    fs::set_permissions(a.join("locked.txt"), fs::Permissions::from_mode(0o222)).unwrap();
    // Root bypasses permission bits (container CI): the scenario does not
    // apply there.
    if fs::read(a.join("locked.txt")).is_ok() {
        return;
    }
    fs::write(a.join("locked.txt"), b"v2\n").unwrap();
    fs::write(a.join("other.txt"), b"two\n").unwrap();

    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("other.txt")).unwrap(), b"two\n");
    assert_eq!(
        fs::read(b.join("locked.txt")).unwrap(),
        b"v1\n",
        "mirror keeps last-good content until the source is readable again"
    );

    // Readable again: the next cycle converges it.
    fs::set_permissions(a.join("locked.txt"), fs::Permissions::from_mode(0o644)).unwrap();
    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("locked.txt")).unwrap(), b"v2\n");
}

#[cfg(unix)]
#[test]
fn unreadable_directory_is_skipped() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("good.txt"), b"good\n").unwrap();
    // An unreadable directory must be skipped, not freeze the workspace.
    let sealed = a.join("sealed");
    fs::create_dir_all(&sealed).unwrap();
    fs::set_permissions(&sealed, fs::Permissions::from_mode(0o000)).unwrap();
    // Root bypasses permission bits (container CI): the scenario does not
    // apply there.
    if fs::read_dir(&sealed).is_ok() {
        return;
    }

    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("good.txt")).unwrap(), b"good\n");

    fs::set_permissions(&sealed, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn unreadable_directory_keeps_mirror_subtree() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::create_dir_all(a.join("sub")).unwrap();
    fs::write(a.join("sub/keep.txt"), b"keep\n").unwrap();
    fs::write(a.join("top.txt"), b"top\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Seal the subdirectory: the mirror must keep the last-good subtree,
    // not delete it, while everything else still converges.
    fs::set_permissions(a.join("sub"), fs::Permissions::from_mode(0o000)).unwrap();
    // Root bypasses permission bits (container CI): scenario not applicable.
    if fs::read_dir(a.join("sub")).is_ok() {
        return;
    }
    fs::write(a.join("top.txt"), b"top v2\n").unwrap();
    sync_cycle(a, b).unwrap();

    assert_eq!(fs::read(b.join("top.txt")).unwrap(), b"top v2\n");
    assert_eq!(
        fs::read(b.join("sub/keep.txt")).unwrap(),
        b"keep\n",
        "mirror must keep the last-good subtree during a transient outage"
    );

    fs::set_permissions(a.join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn unreadable_stat_keeps_mirror_copy() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::create_dir_all(a.join("sub")).unwrap();
    fs::write(a.join("sub/keep.txt"), b"keep\n").unwrap();
    fs::write(a.join("top.txt"), b"top\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Read-but-no-execute directory: entries list, but stat of the files
    // inside fails EACCES. The mirror must keep last-good copies, not
    // delete the subtree.
    fs::set_permissions(a.join("sub"), fs::Permissions::from_mode(0o444)).unwrap();
    // Root bypasses permission bits (container CI): scenario not applicable.
    if fs::metadata(a.join("sub/keep.txt")).is_ok() {
        fs::set_permissions(a.join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    fs::write(a.join("top.txt"), b"top v2\n").unwrap();
    sync_cycle(a, b).unwrap();

    assert_eq!(fs::read(b.join("top.txt")).unwrap(), b"top v2\n");
    assert_eq!(
        fs::read(b.join("sub/keep.txt")).unwrap(),
        b"keep\n",
        "mirror must keep last-good files when stat fails"
    );

    fs::set_permissions(a.join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn git_dir_to_gitfile_transition_converges() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::create_dir_all(a.join(".git/refs")).unwrap();
    fs::write(a.join(".git/HEAD"), b"ref\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Transition: `.git/` directory -> `.git` gitfile (worktree style).
    // The gitfile write must be ordered after the old contents' deletes.
    fs::remove_dir_all(a.join(".git")).unwrap();
    fs::write(a.join(".git"), b"gitdir: /elsewhere/.git/worktrees/x\n").unwrap();
    sync_cycle(a, b).unwrap();

    assert_eq!(
        fs::read(b.join(".git")).unwrap(),
        b"gitdir: /elsewhere/.git/worktrees/x\n"
    );
}

#[cfg(unix)]
#[test]
fn pear_dirs_and_manifests_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());
    fs::write(a.join(".env"), b"SECRET=1\n").unwrap();
    sync_cycle(a, b).unwrap();

    for dir in [a.join(".pear"), b.join(".pear")] {
        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{} must be owner-only", dir.display());
    }
    for manifest in [a.join(".pear/manifest.json"), b.join(".pear/manifest.json")] {
        let mode = fs::metadata(&manifest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} must be owner-only", manifest.display());
    }
}

#[cfg(unix)]
#[test]
fn unreadable_root_fails_cycle_mirror_untouched() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("keep.txt"), b"keep\n").unwrap();
    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("keep.txt")).unwrap(), b"keep\n");

    // The whole workspace root becomes unreadable: the cycle must fail
    // (never sync an empty scan), and the mirror must keep every file.
    fs::set_permissions(a, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(a).is_ok() {
        // Root bypasses permission bits (container CI): not applicable.
        fs::set_permissions(a, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    assert!(
        sync_cycle(a, b).is_err(),
        "an unreadable workspace root must fail the cycle"
    );
    assert_eq!(
        fs::read(b.join("keep.txt")).unwrap(),
        b"keep\n",
        "mirror must be untouched when the root is unreadable"
    );
    fs::set_permissions(a, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn apply_rejects_symlinked_ancestor() {
    let t_dir = tempdir().unwrap();
    let outside_dir = tempdir().unwrap();
    let (t, outside) = (t_dir.path(), outside_dir.path());

    // A symlinked dir inside the target tree, and a manifest wanting to
    // write through it.
    std::os::unix::fs::symlink(outside, t.join("link")).unwrap();

    let chunk = blake3::hash(b"data").to_hex().to_string();
    let mut files = BTreeMap::new();
    files.insert(
        "link/victim.txt".to_string(),
        pear_core::manifest::FileEntry {
            size: 4,
            mode: 0o644,
            mtime_secs: 1,
            mtime_nanos: 0,
            chunks: vec![chunk.clone()],
        },
    );
    let new = pear_core::manifest::Manifest {
        version: 1,
        workspace_id: "ws".to_string(),
        scanned_at_secs: 0,
        files,
    };
    let store = pear_core::store::LocalStore::open(t.join(".pear/store")).unwrap();
    pear_core::store::ChunkSink::put(&store, &chunk, b"data").unwrap();

    let old = pear_core::manifest::Manifest::new("ws".to_string());
    let result = pear_core::apply::apply(t, &old, &new, &store);
    assert!(
        result.is_err(),
        "apply must refuse to write through a symlinked ancestor"
    );
    assert!(
        !outside.join("victim.txt").exists(),
        "nothing may be written outside the target"
    );
}

#[test]
fn nested_target_is_rejected_without_side_effects() {
    let a_dir = tempdir().unwrap();
    let a = a_dir.path();
    fs::write(a.join("f.txt"), b"x\n").unwrap();

    let inner = a.join("inner");
    assert!(sync_cycle(a, &inner).is_err());
    assert!(
        !inner.exists(),
        "a rejected sync must not create the target directory"
    );
}

#[cfg(unix)]
#[test]
fn mirror_files_restore_source_mtime() {
    use std::os::unix::fs::MetadataExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("file.txt"), b"content\n").unwrap();
    // A distinct, older mtime: apply-time would be visibly wrong.
    filetime::set_file_mtime(
        a.join("file.txt"),
        filetime::FileTime::from_unix_time(1_600_000_000, 123_000_000),
    )
    .unwrap();

    sync_cycle(a, b).unwrap();
    let md = fs::metadata(b.join("file.txt")).unwrap();
    assert_eq!(md.mtime(), 1_600_000_000);
    assert_eq!(md.mtime_nsec(), 123_000_000);
}

#[test]
fn reverse_sync_rewrites_nothing() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::create_dir_all(a.join("src")).unwrap();
    fs::write(a.join("src/main.rs"), b"fn main() {}\n").unwrap();
    fs::write(a.join("notes.txt"), b"notes\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Reverse roles: the mirror is metadata-faithful, so nothing is
    // considered changed and nothing is rewritten on the old writer.
    let r = sync_cycle(b, a).unwrap();
    assert!(
        r.written.is_empty() && r.deleted.is_empty(),
        "reverse sync must be a no-op for file writes, got written={:?} deleted={:?}",
        r.written,
        r.deleted
    );
}

#[cfg(unix)]
#[test]
fn failed_upload_skips_files_not_cycle() {
    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    // Two files sharing identical content (shared chunk), plus another.
    fs::write(a.join("f1.txt"), b"shared v1\n").unwrap();
    fs::write(a.join("f2.txt"), b"shared v1\n").unwrap();
    fs::write(a.join("other.txt"), b"other v1\n").unwrap();
    sync_cycle(a, b).unwrap();

    // Make the mirror's store unwritable, then change everything.
    set_mode_recursive(&b.join(".pear/store"), 0o555);
    fs::write(a.join("f1.txt"), b"shared v2\n").unwrap();
    fs::write(a.join("f2.txt"), b"shared v2\n").unwrap();
    fs::write(a.join("other.txt"), b"other v2\n").unwrap();

    // Uploads fail, but the cycle must skip the affected files rather than
    // fail wholesale (a poisoned dedupe set would fail the apply instead).
    // As root the store stays writable and the cycle simply converges.
    sync_cycle(a, b).unwrap();

    // Store writable again: the next cycle converges everything.
    set_mode_recursive(&b.join(".pear/store"), 0o755);
    sync_cycle(a, b).unwrap();
    assert_eq!(fs::read(b.join("f1.txt")).unwrap(), b"shared v2\n");
    assert_eq!(fs::read(b.join("f2.txt")).unwrap(), b"shared v2\n");
    assert_eq!(fs::read(b.join("other.txt")).unwrap(), b"other v2\n");
}

#[cfg(unix)]
fn set_mode_recursive(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    for entry in fs::read_dir(path).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            set_mode_recursive(&p, mode);
        }
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A manifest is network input: setuid/setgid/sticky bits must never
/// materialize on a mirror, even when the writer's own file carries them
/// (the writer's manifest keeps the true bits; apply masks them).
#[cfg(unix)]
#[test]
fn apply_masks_setuid_bits_from_manifests() {
    use std::os::unix::fs::PermissionsExt;

    let a_dir = tempdir().unwrap();
    let b_dir = tempdir().unwrap();
    let (a, b) = (a_dir.path(), b_dir.path());

    fs::write(a.join("priv.sh"), b"#!/bin/sh\nid\n").unwrap();
    fs::set_permissions(a.join("priv.sh"), fs::Permissions::from_mode(0o6755)).unwrap();
    fs::write(a.join("plain.txt"), b"p\n").unwrap();

    sync_cycle(a, b).unwrap();

    let applied = mode_of(&b.join("priv.sh")) & 0o7777;
    assert_eq!(
        applied, 0o755,
        "setuid/setgid bits must be masked on apply, got {applied:o}"
    );
    // The writer's own manifest still records the true mode (no
    // information is lost locally — the mask is the trust boundary).
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(a.join(".pear/manifest.json")).unwrap()).unwrap();
    let recorded = manifest["files"]["priv.sh"]["mode"].as_u64().unwrap();
    assert_eq!(recorded, 0o6755, "the writer's manifest keeps true bits");
}

/// Keys differing only in case are legal on a case-sensitive writer but
/// resolve to ONE file on a case-insensitive mirror: the pull must fail
/// loudly, not misapply (write both to one path, then let a delete of
/// one remove the file the other claims exists).
#[test]
fn apply_refuses_case_colliding_manifests() {
    use pear_core::manifest::{FileEntry, Manifest};
    use pear_core::store::LocalStore;

    let tmp = tempdir().unwrap();
    let target = tmp.path().join("t");
    fs::create_dir_all(&target).unwrap();
    let store = LocalStore::open(tmp.path().join("store")).unwrap();

    let mut new = Manifest::new("ws".into());
    let entry = || FileEntry {
        size: 0,
        mode: 0o644,
        mtime_secs: 0,
        mtime_nanos: 0,
        chunks: Vec::new(),
    };
    new.files.insert("README".to_string(), entry());
    new.files.insert("readme".to_string(), entry());

    let old = Manifest::new("ws".into());
    let err = match pear_core::apply::apply(&target, &old, &new, &store) {
        Ok(_) => panic!("case-colliding manifest must fail the pull"),
        Err(e) => e,
    };
    // Typed, so mirror loops classify it as fatal (never retried) rather
    // than a transient cycle error.
    assert!(
        err.downcast_ref::<pear_core::apply::ApplyRejection>()
            .is_some(),
        "expected ApplyRejection, got {err:#}"
    );
    assert!(
        format!("{err:#}").contains("collide"),
        "case-colliding keys must fail the pull: {err:#}"
    );
}
