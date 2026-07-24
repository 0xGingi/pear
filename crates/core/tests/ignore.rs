use std::collections::BTreeSet;
use std::fs;

use tempfile::tempdir;

#[test]
fn env_files_override_gitignore() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join(".gitignore"), "*.log\n.env\n").unwrap();
    fs::write(root.join("app.log"), b"log\n").unwrap();
    fs::write(root.join(".env"), b"SECRET=1\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/.env.local"), b"A=1\n").unwrap();
    fs::create_dir_all(root.join("node_modules/leftpad")).unwrap();
    fs::write(root.join("node_modules/leftpad/index.js"), b"x\n").unwrap();
    fs::create_dir_all(root.join("target/debug")).unwrap();
    fs::write(root.join("target/debug/app"), b"bin\n").unwrap();
    fs::create_dir_all(root.join(".git/objects")).unwrap();
    fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    // `.env*` syncs even though `.gitignore` ignores it.
    assert!(paths.contains(".env"));
    assert!(paths.contains("sub/.env.local"));
    assert!(paths.contains("main.rs"));
    // `.git/` syncs (dotfiles are not hidden from us).
    assert!(paths.contains(".git/HEAD"));
    assert!(!paths.contains("app.log"), "*.log must stay ignored");
    assert!(
        !paths.iter().any(|p| p.starts_with("node_modules/")),
        "node_modules must stay excluded"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("target/")),
        "target must stay excluded"
    );
}

#[test]
fn git_internals_ignore_user_gitignore() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // `logs/` is a common pattern; it must not filter `.git/logs/`.
    fs::write(root.join(".gitignore"), "logs/\n").unwrap();
    fs::create_dir_all(root.join("logs")).unwrap();
    fs::write(root.join("logs/app.log"), b"noise\n").unwrap();
    fs::create_dir_all(root.join(".git/logs/refs")).unwrap();
    fs::write(root.join(".git/logs/HEAD"), b"commit A\n").unwrap();
    fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    assert!(paths.contains(".git/logs/HEAD"));
    assert!(paths.contains(".git/HEAD"));
    assert!(paths.contains("main.rs"));
    assert!(
        !paths.contains("logs/app.log"),
        "gitignore still applies outside .git"
    );
}

#[test]
fn pear_dir_excluded_case_insensitively() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // Manifest validation rejects `.pear` case-insensitively, so scan must
    // exclude it case-insensitively too — otherwise the tool would produce
    // manifests its own validator rejects.
    fs::create_dir_all(root.join(".PEAR")).unwrap();
    fs::write(root.join(".PEAR/secret.txt"), b"x\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    assert!(paths.contains("main.rs"));
    assert!(
        !paths
            .iter()
            .any(|p| p.eq_ignore_ascii_case(".pear/secret.txt")),
        ".PEAR must be excluded like .pear"
    );
}

#[test]
fn pear_file_excluded_case_insensitively() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // A root-level *file* named `.PEAR` (possible on case-sensitive
    // filesystems) would fail manifest validation; scan must never
    // produce it.
    fs::write(root.join(".PEAR"), b"x\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    assert!(paths.contains("main.rs"));
    assert!(!paths.iter().any(|p| p.eq_ignore_ascii_case(".pear")));
}

#[test]
fn git_internals_ignore_builtin_excludes() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // A hierarchical branch named `build/x` creates directories under
    // `.git/refs/heads/build/` — built-in excludes must not prune inside
    // `.git`, or the unpushed branch silently never syncs.
    fs::create_dir_all(root.join(".git/refs/heads/build")).unwrap();
    fs::write(root.join(".git/refs/heads/build/x"), b"ref\n").unwrap();
    fs::create_dir_all(root.join(".git/logs/refs/heads/build")).unwrap();
    fs::write(root.join(".git/logs/refs/heads/build/x"), b"log\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    assert!(paths.contains(".git/refs/heads/build/x"));
    assert!(paths.contains(".git/logs/refs/heads/build/x"));
    assert!(paths.contains("main.rs"));
}

#[cfg(unix)]
#[test]
fn skipped_entries_are_recorded() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("real.txt"), b"x\n").unwrap();
    std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

    let outcome = pear_core::scan::scan(root).unwrap();
    assert!(outcome.files.iter().any(|f| f.rel_path == "real.txt"));
    assert!(
        outcome.skipped.iter().any(|p| p == "link.txt"),
        "symlinks must be recorded as skipped, not vanish silently"
    );
}

#[test]
fn builtin_excluded_dirs_are_recorded() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::create_dir_all(root.join("node_modules/leftpad")).unwrap();
    fs::write(root.join("node_modules/leftpad/index.js"), b"x\n").unwrap();
    fs::create_dir_all(root.join("build/generated")).unwrap();
    fs::write(root.join("build/generated/out.rs"), b"y\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let outcome = pear_core::scan::scan(root).unwrap();
    assert!(outcome.files.iter().any(|f| f.rel_path == "main.rs"));
    assert!(outcome.excluded.iter().any(|p| p == "node_modules"));
    assert!(outcome.excluded.iter().any(|p| p == "build"));
}

#[test]
fn pear_toml_include_rescues_tracked_build_dir() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::create_dir_all(root.join("build/generated")).unwrap();
    fs::write(root.join("build/generated/out.rs"), b"y\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    // Default: a tracked dir named `build` is still name-excluded (M1).
    let outcome = pear_core::scan::scan(root).unwrap();
    assert!(
        !outcome
            .files
            .iter()
            .any(|f| f.rel_path.starts_with("build/")),
        "build must stay excluded without pear.toml"
    );
    assert!(outcome.excluded.iter().any(|p| p == "build"));

    // `[sync].include` re-includes it from the next scan cycle on.
    fs::write(root.join("pear.toml"), "[sync]\ninclude = [\"build\"]\n").unwrap();
    let outcome = pear_core::scan::scan(root).unwrap();
    let paths: BTreeSet<&str> = outcome.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(paths.contains("build/generated/out.rs"));
    assert!(
        paths.contains("pear.toml"),
        "pear.toml syncs as a normal worktree file"
    );
    assert!(
        !outcome.excluded.iter().any(|p| p == "build"),
        "an included dir is no longer reported as excluded"
    );
}

#[test]
fn pear_toml_exclude_wins_over_include_and_files() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::create_dir_all(root.join("build/generated")).unwrap();
    fs::write(root.join("build/lib.rs"), b"x\n").unwrap();
    fs::write(root.join("build/generated/out.rs"), b"y\n").unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/main.rs"), b"fn main() {}\n").unwrap();
    // `.env*` syncs even gitignored, but a user `exclude` outranks that
    // exception too (§4: sync-by-default is overridable in pear.toml).
    fs::write(root.join(".env"), b"A=1\n").unwrap();

    fs::write(
        root.join("pear.toml"),
        "[sync]\ninclude = [\"build\"]\nexclude = [\"build/generated\", \"src\", \".env\"]\n",
    )
    .unwrap();

    let outcome = pear_core::scan::scan(root).unwrap();
    let paths: BTreeSet<&str> = outcome.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(
        paths.contains("build/lib.rs"),
        "include still covers the rest of build/"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("build/generated/")),
        "exclude beats include"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("src/")),
        "exclude drops normal files too"
    );
    assert!(!paths.contains(".env"), "exclude beats the .env exception");
    // User excludes surface in `excluded` like built-in name excludes.
    assert!(outcome.excluded.iter().any(|p| p == "build/generated"));
    assert!(outcome.excluded.iter().any(|p| p == "src"));
}

#[test]
fn pear_toml_include_matches_root_relative_prefixes() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::create_dir_all(root.join("build")).unwrap();
    fs::write(root.join("build/lib.rs"), b"x\n").unwrap();
    // `rebuild/` is an ordinary dir the entry must not match, and the
    // `build` name *inside* it stays built-in-excluded: entries are
    // root-relative prefixes, not name matches.
    fs::create_dir_all(root.join("rebuild/build")).unwrap();
    fs::write(root.join("rebuild/notes.txt"), b"n\n").unwrap();
    fs::write(root.join("rebuild/build/out.rs"), b"y\n").unwrap();
    fs::write(root.join("pear.toml"), "[sync]\ninclude = [\"build\"]\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(paths.contains("build/lib.rs"));
    assert!(paths.contains("rebuild/notes.txt"));
    assert!(
        !paths.contains("rebuild/build/out.rs"),
        "include = [\"build\"] must not rescue rebuild/build"
    );
}

#[test]
fn pear_toml_include_reaches_below_a_builtin_excluded_dir() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // An include targeting a DESCENDANT of a built-in-excluded dir: the
    // walk must descend far enough to reach it (previously the ancestor
    // was pruned first and the deep entry silently did nothing).
    fs::create_dir_all(root.join("build/generated")).unwrap();
    fs::write(root.join("build/generated/keep.rs"), b"k\n").unwrap();
    fs::write(root.join("build/other.txt"), b"o\n").unwrap();
    fs::create_dir_all(root.join("build/other")).unwrap();
    fs::write(root.join("build/other/inner.txt"), b"i\n").unwrap();
    fs::write(
        root.join("pear.toml"),
        "[sync]\ninclude = [\"build/generated\"]\n",
    )
    .unwrap();

    let outcome = pear_core::scan::scan(root).unwrap();
    let paths: BTreeSet<&str> = outcome.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(paths.contains("build/generated/keep.rs"));
    assert!(
        !paths.contains("build/other.txt") && !paths.contains("build/other/inner.txt"),
        "the rest of the excluded tree stays unsynced"
    );
    assert!(
        outcome.excluded.iter().any(|p| p == "build/other"),
        "the shadowed subtree is reported as excluded: {:?}",
        outcome.excluded
    );
    assert!(
        !outcome.excluded.iter().any(|p| p == "build"),
        "the partially-reached dir is not wholly excluded: {:?}",
        outcome.excluded
    );
}

#[test]
fn nested_pear_dirs_sync_but_root_pear_never_does() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // The root `.pear` is pear's own metadata: never synced. A `.pear`
    // directory at any deeper level is ordinary content (a vendored
    // fixture) — manifest validation only rejects first-component
    // `.pear`, so pruning it would silently omit valid files.
    fs::create_dir_all(root.join(".pear/store")).unwrap();
    fs::write(root.join(".pear/manifest.json"), b"{}\n").unwrap();
    fs::create_dir_all(root.join("sub/.pear")).unwrap();
    fs::write(root.join("sub/.pear/fixture.json"), b"{}\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let outcome = pear_core::scan::scan(root).unwrap();
    let paths: BTreeSet<&str> = outcome.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(paths.contains("sub/.pear/fixture.json"));
    assert!(paths.contains("main.rs"));
    assert!(
        !paths
            .iter()
            .any(|p| *p == ".pear" || p.starts_with(".pear/")),
        "the root metadata dir never syncs"
    );
}

#[test]
fn pear_toml_include_overrides_gitignore() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // `build` is BOTH gitignored and built-in-name-excluded; `gen` is
    // gitignored only. Pass 1 never sees either (gitignore filters
    // before our predicate runs), so the include can only reach them in
    // the ignore-rules-off walk — the §14 precedence `include` >
    // built-in excludes > gitignore depends on it.
    fs::write(root.join(".gitignore"), "build\ngen\n").unwrap();
    fs::create_dir_all(root.join("build")).unwrap();
    fs::write(root.join("build/lib.rs"), b"x\n").unwrap();
    fs::create_dir_all(root.join("gen/out")).unwrap();
    fs::write(root.join("gen/out/keep.txt"), b"k\n").unwrap();
    fs::write(root.join("gen/skip.txt"), b"s\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();
    fs::write(
        root.join("pear.toml"),
        "[sync]\ninclude = [\"build\", \"gen/out\"]\n",
    )
    .unwrap();

    let outcome = pear_core::scan::scan(root).unwrap();
    let paths: BTreeSet<&str> = outcome.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(
        paths.contains("build/lib.rs"),
        "include must override gitignore on a name-excluded dir"
    );
    assert!(
        paths.contains("gen/out/keep.txt"),
        "include must override gitignore on an ordinary dir"
    );
    assert!(
        !paths.contains("gen/skip.txt"),
        "outside the include prefix, gitignore still applies"
    );
    assert!(paths.contains("main.rs"));
}

#[test]
fn unparseable_pear_toml_warns_and_scans_without_overrides() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join("pear.toml"), "[sync\ninclude = [\"build\"\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();
    fs::create_dir_all(root.join("build")).unwrap();
    fs::write(root.join("build/lib.rs"), b"x\n").unwrap();

    // The bad config warns (stderr, once per scan cycle) and the scan
    // proceeds as if the file were absent.
    let outcome = pear_core::scan::scan(root).unwrap();
    let paths: BTreeSet<&str> = outcome.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert!(paths.contains("main.rs"));
    assert!(
        paths.contains("pear.toml"),
        "an unparseable pear.toml still syncs as a normal file"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("build/")),
        "built-in excludes still apply"
    );
    assert!(outcome.excluded.iter().any(|p| p == "build"));
}

#[cfg(unix)]
#[test]
fn gitignored_non_utf8_names_are_not_recorded_as_skipped() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join(".gitignore"), b"*.log\n").unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();
    // A gitignored file with a non-UTF-8 name is outside the sync set; it
    // must not be recorded in `skipped` (strict captures would bail on a
    // path they were never meant to capture). APFS refuses non-UTF-8
    // names, in which case the scenario does not apply here.
    if fs::write(root.join(OsStr::from_bytes(b"bad-\xff.log")), b"x\n").is_err() {
        return;
    }

    let outcome = pear_core::scan::scan(root).unwrap();
    assert!(outcome.files.iter().any(|f| f.rel_path == "main.rs"));
    assert!(
        outcome.skipped.is_empty(),
        "a gitignored non-UTF-8 file is outside the sync set: {:?}",
        outcome.skipped
    );
}

/// §28: the kill switch forbids EXACTLY what the product promise syncs.
/// With a gitignore that hides everything, the captured set must be
/// precisely the files `is_dotenv` names — the same definition the relay's
/// 409 and the writer's refusal apply, so nothing slips through (or gets
/// caught) by a definition drift.
#[test]
fn dotenv_capture_set_matches_is_dotenv_exactly() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    fs::write(root.join(".gitignore"), "*\n").unwrap();
    // The .env* boundary, on both sides...
    fs::write(root.join(".env"), b"SECRET=1\n").unwrap();
    fs::write(root.join(".envrc"), b"use nix\n").unwrap();
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::write(root.join("sub/.env.local"), b"A=1\n").unwrap();
    // ...including names that are NOT .env* by the scanner's rule.
    fs::write(root.join("env"), b"not it\n").unwrap();
    fs::write(root.join("foo.env"), b"not it\n").unwrap();
    fs::write(root.join(".ENV"), b"not it (case)\n").unwrap();
    fs::create_dir_all(root.join(".env.d")).unwrap();
    fs::write(
        root.join(".env.d/local"),
        b"contents of a .env* DIR are not .env*\n",
    )
    .unwrap();
    fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();

    let files = pear_core::scan::scan(root).unwrap().files;
    let paths: BTreeSet<&str> = files.iter().map(|f| f.rel_path.as_str()).collect();

    // Every captured path satisfies is_dotenv, and every is_dotenv file on
    // disk was captured: the two definitions cannot drift apart.
    assert!(
        paths.iter().all(|p| pear_core::scan::is_dotenv(p)),
        "everything captured under an ignore-all gitignore is .env*: {paths:?}"
    );
    for expected in [".env", ".envrc", "sub/.env.local"] {
        assert!(paths.contains(expected), "{expected} must sync");
    }
    for rejected in ["env", "foo.env", ".ENV", ".env.d/local", "main.rs"] {
        assert!(!paths.contains(rejected), "{rejected} must not sync");
    }
}
