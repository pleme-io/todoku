//! `gh-owner` — run `gh` with the credential that belongs to the repository's
//! owner.
//!
//! # Why this exists
//!
//! `gh` reads exactly one `GH_TOKEN`. Fine-grained PATs are bound to exactly
//! one resource owner. Those two facts together mean a global `GH_TOKEN` export
//! is not a configuration, it is **a choice of which org to break**: the
//! akeylesslabs token answers `404` for pleme-io and vice versa.
//!
//! The alternative people actually use — `GH_TOKEN=$(cat …) gh …` typed by
//! hand per call — is the thing this replaces. It puts the routing decision in
//! human memory, which is where it was before
//! `nix/lib/github-token-scopes.nix` existed for the flake-fetch path.
//!
//! # How the owner is determined
//!
//! 1. An explicit `--repo`/`-R` argument, in any form `gh` accepts.
//! 2. Otherwise a positional `owner/repo` argument — `gh repo view owner/repo`,
//!    `gh repo clone owner/repo` — but ONLY when the table already knows that
//!    owner. That condition is what makes the heuristic safe: `gh` has other
//!    slash-bearing positionals (a branch name, an API path), and the cost of
//!    guessing wrong is using the wrong credential. If the candidate owner is
//!    in the table, using its token is correct whatever the argument meant; if
//!    it is not, the guess is discarded rather than acted on.
//! 3. Otherwise the current repository's `origin` remote.
//!
//! Step 3 reads `.git/config` **directly, with no subprocess**. That is not
//! purity for its own sake: shelling out to `git` can fire a credential helper
//! (on macOS, a keychain GUI prompt) in the middle of what should be a
//! read-only lookup — the same reason `formigueiro` refuses git subprocesses.
//!
//! # What it does with an unresolved owner
//!
//! Runs `gh` with no injected token, letting `gh`'s own auth apply. It never
//! substitutes a different owner's credential, because a token asserted over a
//! scope it does not hold is the exact defect the credential table exists to
//! prevent.
//!
//! # Transparency contract
//!
//! This binary is also installed AS `gh`, ahead of the real one on PATH, so
//! every consumer — scripts, MCP servers, muscle memory — gets owner-correct
//! credentials without knowing this exists. Four properties make that
//! substitution honest rather than a leaky alias, and each is load-bearing:
//!
//! 1. **argv passes through verbatim.** Only the environment is added.
//! 2. **`exec`, not spawn.** The process is REPLACED, so the tty, signal
//!    disposition and exit status are those of a direct `gh` call. A spawning
//!    wrapper would break `gh`'s interactive prompts and swallow signals.
//! 3. **Unresolved means untouched.** No owner, no table, or an unknown owner
//!    all run `gh` with nothing injected — byte-identical to invoking it
//!    directly.
//! 4. **It can never exec itself.** [`real_gh`] walks PATH but skips any
//!    candidate that canonicalizes to this same executable. Resolving a bare
//!    `gh` while installed AS `gh` is an infinite exec loop, and it presents
//!    as a silently hung terminal rather than as an error — so the guard is
//!    structural, not a convention.

use std::path::{Path, PathBuf};
use std::process::Command;

use todoku::credentials::{
    CredentialTable, Resolution, owner_from_remote_url, owner_from_repo_arg,
};

/// Absolute path of the REAL `gh`.
///
/// This binary is installed under the name `gh`, AHEAD of the real one on
/// PATH, so `Command::new("gh")` would exec this program again — forever. That
/// failure presents as a silently hung terminal with no message, so it is
/// closed structurally rather than by convention.
///
/// The resolution walks PATH and **skips any candidate that is this same
/// executable**, compared by canonicalized path against
/// [`std::env::current_exe`]. That is self-contained: it needs no build-time
/// coupling to a `gh` store path, it keeps working if the packaging changes,
/// and it cannot select itself even if installed under several names or
/// symlinked from several PATH entries.
///
/// `REAL_GH` (compile-time) and `GH_OWNER_REAL_GH` (runtime) override the
/// search when a caller wants an exact, pinned binary.
fn real_gh() -> Result<PathBuf, String> {
    if let Some(p) = option_env!("REAL_GH").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("GH_OWNER_REAL_GH").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }

    // Our own identity, canonicalized. If this cannot be determined we must
    // NOT fall back to a bare `gh`: without it there is no way to tell the
    // real one from ourselves.
    let me = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| {
            format!("cannot determine own path ({e}), so `gh` cannot be resolved safely")
        })?;

    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is unset".to_string())?;
    let mut skipped_self = false;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("gh");
        let Ok(canonical) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if canonical == me {
            skipped_self = true;
            continue;
        }
        if is_executable(&canonical) {
            return Ok(candidate);
        }
    }
    Err(if skipped_self {
        "no `gh` on PATH other than this wrapper — the real gh is not installed, or is shadowed \
         only by us"
            .to_string()
    } else {
        "no `gh` found on PATH".to_string()
    })
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().is_some_and(|a| a == "--gh-owner-explain") {
        return explain(&args[1..]);
    }

    let table = CredentialTable::load_default();
    let owner = determine_owner(&args, table.as_ref().ok());

    let gh = match real_gh() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gh-owner: {e}");
            return std::process::ExitCode::from(127);
        }
    };
    let mut cmd = Command::new(&gh);
    cmd.args(&args);

    if let Some(owner) = owner.as_deref() {
        match &table {
            Ok(table) => match table.resolve(owner) {
                Resolution::Found { token, .. } => {
                    cmd.env("GH_TOKEN", token.expose());
                    // GITHUB_TOKEN too: gh reads GH_TOKEN first, but child
                    // processes gh spawns (extensions, hub-compatible tools)
                    // commonly read GITHUB_TOKEN.
                    cmd.env("GITHUB_TOKEN", token.expose());
                }
                // A defect is worth a word on stderr — it is the difference
                // between "gh is unauthenticated" and "your token file is
                // empty", which otherwise both surface as an opaque 401.
                other @ (Resolution::Missing { .. } | Resolution::Empty { .. }) => {
                    eprintln!("gh-owner: {}", describe(&other));
                }
                // Not a problem: anonymous, or gh's own auth, is correct.
                Resolution::UnknownOwner { .. } => {}
            },
            Err(e) => eprintln!("gh-owner: {e}"),
        }
    }

    exec_or_spawn(cmd)
}

/// Report what WOULD happen, without running `gh` and without printing a
/// token. This is the surface to reach for when a call is failing and you need
/// to know whether the credential or the request is at fault.
fn explain(rest: &[String]) -> std::process::ExitCode {
    println!(
        "gh: {}",
        real_gh().map_or_else(
            |e| format!("<unresolved> — {e}"),
            |p| p.display().to_string()
        )
    );
    let table = CredentialTable::load_default();
    match determine_owner(rest, table.as_ref().ok()) {
        None => println!("owner: <undetermined> — gh's own auth applies"),
        Some(owner) => {
            println!("owner: {owner}");
            match &table {
                Ok(table) => println!("resolution: {}", describe(&table.resolve(&owner))),
                Err(e) => println!("resolution: table unavailable — {e}"),
            }
        }
    }
    std::process::ExitCode::SUCCESS
}

/// The owner this invocation is about: an explicit flag, else a
/// table-confirmed positional, else the cwd's `origin`. See the module docs
/// for why the positional pass is gated on the table.
fn determine_owner(args: &[String], table: Option<&CredentialTable>) -> Option<String> {
    owner_from_args(args)
        .or_else(|| table.and_then(|t| owner_from_positional(args, t)))
        .or_else(|| owner_from_cwd_remote(Path::new(".")))
}

/// A positional `owner/repo` whose owner the table already declares.
fn owner_from_positional(args: &[String], table: &CredentialTable) -> Option<String> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .filter_map(|a| owner_from_repo_arg(a))
        .find(|owner| table.owners().any(|(known, _)| known == *owner))
        .map(str::to_string)
}

fn describe(r: &Resolution) -> String {
    match r {
        Resolution::Found { owner, token } => {
            format!("credential for {owner} ({} bytes)", token.len())
        }
        Resolution::UnknownOwner { owner } => {
            format!("{owner} is not in the credential table — proceeding without a token")
        }
        Resolution::Missing { owner, path } => format!(
            "{owner} is declared but {} does not exist (declared in nix, not rebuilt?)",
            path.display()
        ),
        Resolution::Empty { owner, path } => format!(
            "{owner} is declared but {} is EMPTY — an empty token authenticates as nobody \
             and GitHub answers 401 Bad credentials, which looks exactly like a revoked token",
            path.display()
        ),
    }
}

/// The owner named by an explicit `--repo`/`-R` argument, in the forms `gh`
/// accepts: `--repo X`, `--repo=X`, `-R X`, `-RX`.
fn owner_from_args(args: &[String]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let candidate = if a == "--repo" || a == "-R" {
            it.next().map(String::as_str)
        } else if let Some(v) = a.strip_prefix("--repo=") {
            Some(v)
        } else if let Some(v) = a.strip_prefix("-R").filter(|v| !v.is_empty()) {
            Some(v)
        } else {
            None
        };
        if let Some(owner) = candidate.and_then(owner_from_repo_arg) {
            return Some(owner.to_string());
        }
    }
    None
}

/// The owner of `origin` for the repository containing `start`, read straight
/// out of `.git/config`. No subprocess — see the module docs.
fn owner_from_cwd_remote(start: &Path) -> Option<String> {
    let config = find_git_config(start)?;
    let text = std::fs::read_to_string(config).ok()?;
    remote_origin_url(&text).and_then(|u| owner_from_remote_url(u).map(str::to_string))
}

/// Walk up from `start` looking for `.git/config`, handling the worktree case
/// where `.git` is a FILE containing `gitdir: <path>` rather than a directory.
fn find_git_config(start: &Path) -> Option<PathBuf> {
    let mut dir = std::fs::canonicalize(start).ok()?;
    loop {
        let dot_git = dir.join(".git");
        if dot_git.is_dir() {
            let cfg = dot_git.join("config");
            if cfg.is_file() {
                return Some(cfg);
            }
        } else if dot_git.is_file() {
            // A linked worktree: `.git` holds `gitdir: /path/to/.git/worktrees/x`.
            // The remote lives in the MAIN repo's config, which is two levels up
            // from the worktree dir. Falling back to the worktree's own config
            // would find no remote at all.
            if let Ok(text) = std::fs::read_to_string(&dot_git) {
                if let Some(p) = text.trim().strip_prefix("gitdir:") {
                    let gitdir = PathBuf::from(p.trim());
                    for candidate in [
                        gitdir.join("config"),
                        gitdir
                            .parent()
                            .and_then(Path::parent)
                            .map(|d| d.join("config"))
                            .unwrap_or_default(),
                    ] {
                        if candidate.is_file() {
                            return Some(candidate);
                        }
                    }
                }
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// The `url` of `[remote "origin"]` in git config text.
fn remote_origin_url(config: &str) -> Option<&str> {
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // Both `[remote "origin"]` and the subsection-less spelling.
            in_origin = line.replace(' ', "") == "[remote\"origin\"]";
            continue;
        }
        if in_origin {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "url" {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

/// Replace this process with `gh` on unix so the terminal, signals and exit
/// status behave exactly as a direct `gh` invocation. `spawn` is the portable
/// fallback.
fn exec_or_spawn(mut cmd: Command) -> std::process::ExitCode {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        // exec only returns on failure.
        eprintln!("gh-owner: cannot run gh: {err}");
        return std::process::ExitCode::from(127);
    }
    #[cfg(not(unix))]
    {
        match cmd.status() {
            Ok(s) => std::process::ExitCode::from(u8::try_from(s.code().unwrap_or(1)).unwrap_or(1)),
            Err(e) => {
                eprintln!("gh-owner: cannot run gh: {e}");
                std::process::ExitCode::from(127)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn reads_every_repo_flag_spelling_gh_accepts() {
        for args in [
            v(&[
                "pr",
                "view",
                "5075",
                "--repo",
                "akeylesslabs/frontend-react",
            ]),
            v(&["pr", "view", "--repo=akeylesslabs/frontend-react"]),
            v(&["pr", "view", "-R", "akeylesslabs/frontend-react"]),
            v(&["pr", "view", "-Rakeylesslabs/frontend-react"]),
        ] {
            assert_eq!(
                owner_from_args(&args).as_deref(),
                Some("akeylesslabs"),
                "failed for {args:?}"
            );
        }
    }

    #[test]
    fn no_repo_flag_yields_no_owner() {
        assert_eq!(owner_from_args(&v(&["pr", "list"])), None);
        // A bare owner is not a repo argument, so it must not resolve.
        assert_eq!(
            owner_from_args(&v(&["pr", "list", "--repo", "pleme-io"])),
            None
        );
    }

    fn probe_table() -> CredentialTable {
        CredentialTable::from_json(
            r#"{"version":1,"owners":{"pleme-io":{"tokenPath":"/nope","sopsKey":"k"}}}"#,
        )
        .unwrap()
    }

    #[test]
    fn a_positional_repo_is_used_when_the_table_knows_the_owner() {
        let t = probe_table();
        assert_eq!(
            owner_from_positional(&v(&["repo", "view", "pleme-io/nix"]), &t).as_deref(),
            Some("pleme-io")
        );
    }

    #[test]
    fn a_positional_slash_arg_for_an_unknown_owner_is_discarded() {
        // `gh pr view feature/some-branch` must NOT resolve a credential for a
        // phantom owner named "feature". Gating on the table is what makes the
        // positional pass safe rather than a guess.
        let t = probe_table();
        assert_eq!(
            owner_from_positional(&v(&["pr", "view", "feature/some-branch"]), &t),
            None
        );
        assert_eq!(
            owner_from_positional(&v(&["repo", "view", "torvalds/linux"]), &t),
            None
        );
    }

    #[test]
    fn a_flag_beats_a_positional() {
        let t = probe_table();
        let args = v(&["repo", "view", "pleme-io/nix", "--repo", "akeylesslabs/x"]);
        assert_eq!(
            determine_owner(&args, Some(&t)).as_deref(),
            Some("akeylesslabs"),
            "an explicit --repo is authoritative"
        );
    }

    #[test]
    fn real_gh_never_resolves_to_this_binary() {
        // The whole hazard in one assertion: whatever `gh` we pick, it must
        // not be us. Exec'ing ourselves re-enters this binary and hangs with
        // no output — the worst possible failure for a transparent shim.
        let me = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .expect("own path");
        match real_gh() {
            Ok(p) => {
                if let Ok(canonical) = std::fs::canonicalize(&p) {
                    assert_ne!(canonical, me, "resolved `gh` to ourselves — exec loop");
                }
            }
            // No gh installed in the test environment is a fine outcome; a
            // silent bare-name fallback would not be.
            Err(e) => assert!(
                e.contains("no `gh`") || e.contains("cannot determine own path"),
                "unexpected error: {e}"
            ),
        }
    }

    #[test]
    fn finds_the_origin_url() {
        let cfg = "\
[core]
\trepositoryformatversion = 0
[remote \"upstream\"]
\turl = git@github.com:someone-else/fork.git
[remote \"origin\"]
\turl = git@github.com:pleme-io/nix.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
";
        assert_eq!(
            remote_origin_url(cfg),
            Some("git@github.com:pleme-io/nix.git")
        );
    }

    #[test]
    fn upstream_is_not_mistaken_for_origin() {
        // Ordering matters: `upstream` appears first and must be skipped.
        let cfg = "[remote \"upstream\"]\n\turl = git@github.com:wrong/repo.git\n";
        assert_eq!(remote_origin_url(cfg), None);
    }
}
