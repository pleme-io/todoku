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
//! credentials without knowing this exists. Five properties make that
//! substitution honest rather than a leaky alias, and each is load-bearing:
//!
//! 1. **argv passes through verbatim.** Only the environment changes (added for
//!    ordinary calls, removed for gh's own login commands, property 5).
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
//! 5. **gh's own credential commands get gh's own credentials, plus the
//!    context.** `gh auth login/refresh/logout/switch/setup-git` manage gh's
//!    stored login, and gh refuses to touch it while `GH_TOKEN` or
//!    `GITHUB_TOKEN` is set ("The value of the GITHUB_TOKEN environment variable
//!    is being used"). Measured 2026-09-23: `gh auth refresh` was impossible
//!    through this wrapper. Those commands now run with both variables
//!    removed, and a note says which owners the table answers for, because a
//!    refreshed gh login does not change what a table owner's calls use.
//!    `gh auth status` prints the routing first. `gh auth token` prints the
//!    token a call for the resolved owner would use, so
//!    `GH_TOKEN=$(gh auth token)` in a script gets the right org's credential.
//!    See [`Route`].

use std::path::{Path, PathBuf};
use std::process::Command;

use todoku::credentials::{
    CredentialTable, DEFAULT_GRAPHQL_OWNER_ARGS, OwnerEntry, Resolution, owner_from_remote_url,
    owner_from_repo_arg,
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

/// What this invocation is, decided before anything runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// An ordinary gh call: inject the owner's credential (the default).
    Inject,
    /// `gh auth login/refresh/logout/switch/setup-git`: gh's own credential
    /// store, which gh refuses to manage while a token variable is set.
    OwnCredentials,
    /// `gh auth status`: gh's view, preceded by this wrapper's routing.
    Status,
    /// `gh auth token`: the token a call for the resolved owner would use.
    Token,
}

/// The `auth` subcommands that manage gh's own stored login.
const OWN_CREDENTIAL_COMMANDS: [&str; 5] = ["login", "refresh", "logout", "switch", "setup-git"];

fn route(args: &[String]) -> Route {
    let mut words = args.iter().filter(|a| !a.starts_with('-'));
    if words.next().map(String::as_str) != Some("auth") {
        return Route::Inject;
    }
    match words.next().map(String::as_str) {
        Some("status") => Route::Status,
        Some("token") => Route::Token,
        Some(sub) if OWN_CREDENTIAL_COMMANDS.contains(&sub) => Route::OwnCredentials,
        _ => Route::Inject,
    }
}

/// True when `--hostname`/`-h` names a host other than github.com, which the
/// credential table does not cover.
fn names_another_host(args: &[String]) -> bool {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let host = if a == "--hostname" || a == "-h" {
            it.next().map(String::as_str)
        } else {
            a.strip_prefix("--hostname=")
        };
        if let Some(h) = host {
            return h != "github.com";
        }
    }
    false
}

/// Whether an owner's token file answers, never the token itself.
enum TokenState {
    Present(usize),
    Missing,
    Empty,
    NotInTable,
}

impl TokenState {
    fn of(table: &CredentialTable, owner: &str) -> Self {
        match table.resolve(owner) {
            Resolution::Found { token, .. } => Self::Present(token.len()),
            Resolution::Missing { .. } => Self::Missing,
            Resolution::Empty { .. } => Self::Empty,
            Resolution::UnknownOwner { .. } => Self::NotInTable,
        }
    }
}

impl std::fmt::Display for TokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Present(n) => write!(f, "{n} bytes"),
            Self::Missing => f.write_str("MISSING"),
            Self::Empty => f.write_str("EMPTY"),
            Self::NotInTable => f.write_str("not in table"),
        }
    }
}

/// One owner's routing: where its credential comes from and whether it is there.
struct RouteRow<'a> {
    owner: &'a str,
    entry: &'a OwnerEntry,
    state: TokenState,
}

impl std::fmt::Display for RouteRow<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "  {}: sops key {} → {} ({})",
            self.owner,
            self.entry.sops_key,
            self.entry.token_path.display(),
            self.state
        )
    }
}

fn route_rows(table: &CredentialTable) -> Vec<RouteRow<'_>> {
    table
        .owners()
        .map(|(owner, entry)| RouteRow {
            owner,
            entry,
            state: TokenState::of(table, owner),
        })
        .collect()
}

/// Which owner this invocation resolves to.
struct ResolvesTo<'a>(Option<&'a str>);

impl std::fmt::Display for ResolvesTo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(o) => write!(f, "  this invocation resolves to: {o}"),
            None => f.write_str("  this invocation resolves to no owner: gh's own auth applies"),
        }
    }
}

/// The note printed before gh changes its own login.
struct OwnLoginNote<'a>(Vec<&'a str>);

impl std::fmt::Display for OwnLoginNote<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "gh-owner: this changes gh's own login. Calls for {} use the credential table \
             instead, so a permission missing there is granted on that token \
             (`gh auth status` shows which).",
            self.0.join(", ")
        )
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.first().is_some_and(|a| a == "--gh-owner-explain") {
        return explain(&args[1..]);
    }

    let table = CredentialTable::load_default();
    let owner = determine_owner(&args, table.as_ref().ok());
    let route = route(&args);

    // `gh auth token` for a table owner: answer with the routed token, which
    // is what every other call for this owner would use. Anything else falls
    // through to gh's own answer.
    if route == Route::Token && !names_another_host(&args) {
        if let (Some(owner), Ok(table)) = (owner.as_deref(), &table) {
            if let Resolution::Found { token, .. } = table.resolve(owner) {
                println!("{}", token.expose());
                return std::process::ExitCode::SUCCESS;
            }
        }
    }

    let gh = match real_gh() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("gh-owner: {e}");
            return std::process::ExitCode::from(127);
        }
    };
    let mut cmd = Command::new(&gh);
    cmd.args(&args);

    match route {
        Route::OwnCredentials => {
            cmd.env_remove("GH_TOKEN");
            cmd.env_remove("GITHUB_TOKEN");
            if let Ok(table) = &table {
                let owners: Vec<&str> = table.owners().map(|(o, _)| o).collect();
                if !owners.is_empty() {
                    eprintln!("{}", OwnLoginNote(owners));
                }
            }
            return exec_or_spawn(cmd);
        }
        Route::Status => {
            if let Ok(table) = &table {
                eprintln!("gh-owner routing (owners in the table use their own credential):");
                for row in route_rows(table) {
                    eprintln!("{row}");
                }
                eprintln!("{}\n", ResolvesTo(owner.as_deref()));
            }
            // Fall through: the rest of gh sees exactly what gh would see.
        }
        Route::Inject | Route::Token => {}
    }

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
                Ok(table) => {
                    println!("resolution: {}", describe(&table.resolve(&owner)));
                    // Where the credential comes from, so a 403 can be traced to
                    // the token that needs the permission GitHub names in
                    // `x-accepted-github-permissions` (`gh api -i` shows it).
                    if let Some(row) = route_rows(table).into_iter().find(|r| r.owner == owner) {
                        println!("credential: {}", row.to_string().trim_start());
                    }
                }
                Err(e) => println!("resolution: table unavailable — {e}"),
            }
        }
    }
    std::process::ExitCode::SUCCESS
}

fn graphql_owner_args(table: Option<&CredentialTable>) -> Vec<String> {
    table.map_or_else(
        || {
            DEFAULT_GRAPHQL_OWNER_ARGS
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        },
        |t| t.graphql_owner_args.clone(),
    )
}

/// The owner this invocation is about: an explicit flag, else a
/// table-confirmed positional, else the cwd's `origin`. See the module docs
/// for why the positional pass is gated on the table.
fn determine_owner(args: &[String], table: Option<&CredentialTable>) -> Option<String> {
    owner_from_args(args)
        .or_else(|| owner_from_api_path(args))
        .or_else(|| owner_from_graphql(args, &graphql_owner_args(table)))
        .or_else(|| table.and_then(|t| owner_from_positional(args, t)))
        .or_else(|| owner_from_cwd_remote(Path::new(".")))
}

/// The owner embedded in a `gh api` REST path.
///
/// `gh api` carries its target in a PATH rather than in `--repo`, so without
/// this the owner falls through to the cwd's git remote. That is not a cosmetic
/// miss: a call against another org from the wrong directory silently uses the
/// wrong token, and GitHub answers **404** for a private repo rather than 401,
/// so it reads as "does not exist" instead of "wrong credential". Measured:
/// `gh api repos/akeylesslabs/pitr-slack` returned 404 from a pleme-io checkout
/// and the id from the repo's own directory.
///
/// Ordered before the positional lookup because an API path is unambiguous,
/// while a bare `owner/repo` positional is only trusted when the table already
/// declares that owner.
///
/// Only the two path shapes whose second segment IS an owner are read.
/// `/user/...`, `/repositories/{id}` and search endpoints carry no owner and
/// are left alone, so they keep falling through to the cwd as before.
fn owner_from_api_path(args: &[String]) -> Option<String> {
    if !args.iter().any(|a| a == "api") {
        return None;
    }
    // Match the PATH SHAPE rather than positionally hunting for the first
    // non-flag argument. That first attempt read `--method PUT` and took `PUT`
    // as the path, because a flag's VALUE does not begin with a dash. Skipping
    // values needs a flag arity table gh does not publish, so the shape is what
    // is matched: only `repos/…` and `orgs/…` carry an owner in segment two.
    args.iter().find_map(|arg| {
        let path = arg
            .strip_prefix("https://api.github.com/")
            .unwrap_or(arg)
            .trim_start_matches('/');
        let mut seg = path.split('/');
        let owner = match seg.next()? {
            "repos" | "orgs" => seg.next()?,
            _ => return None,
        };
        let owner = owner.split(['?', '#']).next().unwrap_or(owner);
        // A path template such as `repos/{owner}/{repo}` names no real owner.
        if owner.is_empty() || owner.starts_with('{') || owner.starts_with('$') {
            return None;
        }
        Some(owner.to_string())
    })
}

fn owner_from_graphql(args: &[String], keys: &[String]) -> Option<String> {
    if !args.iter().any(|a| a == "api")
        || !args.iter().any(|a| a.trim_start_matches('/') == "graphql")
    {
        return None;
    }
    let mut fields = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if matches!(a.as_str(), "-f" | "-F" | "--field" | "--raw-field") {
            if let Some(v) = it.next() {
                fields.push(v.as_str());
            }
        } else if let Some(v) = a
            .strip_prefix("--field=")
            .or_else(|| a.strip_prefix("--raw-field="))
        {
            fields.push(v);
        }
    }
    let valid = |o: &str| !o.is_empty() && o.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let from_field = keys.iter().find_map(|k| {
        fields
            .iter()
            .find_map(|f| f.strip_prefix(k.as_str())?.strip_prefix('='))
            .filter(|o| valid(o))
    });
    if let Some(o) = from_field {
        return Some(o.to_string());
    }
    let query = fields.iter().find_map(|f| f.strip_prefix("query="))?;
    keys.iter().find_map(|k| {
        literal_argument(query, k)
            .filter(|o| valid(o))
            .map(str::to_string)
    })
}

fn literal_argument<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.match_indices(key).find_map(|(i, _)| {
        let before = query[..i].chars().next_back();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        let rest = query[i + key.len()..]
            .trim_start()
            .strip_prefix(':')?
            .trim_start()
            .strip_prefix('"')?;
        Some(&rest[..rest.find('"')?])
    })
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

    #[test]
    fn api_path_names_the_owner_for_repos_and_orgs() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (args, want) in [
            (
                a(&["api", "repos/akeylesslabs/pitr-slack"]),
                Some("akeylesslabs"),
            ),
            (
                a(&["api", "/repos/akeylesslabs/pitr-slack"]),
                Some("akeylesslabs"),
            ),
            (
                a(&["api", "orgs/akeylesslabs/actions/runner-groups"]),
                Some("akeylesslabs"),
            ),
            (
                a(&["api", "--method", "PUT", "repos/pleme-io/actions/x"]),
                Some("pleme-io"),
            ),
            (
                a(&["api", "repos/akeylesslabs/pitr-slack?foo=1"]),
                Some("akeylesslabs"),
            ),
        ] {
            assert_eq!(owner_from_api_path(&args).as_deref(), want, "{args:?}");
        }
    }

    #[test]
    fn graphql_names_the_owner_from_a_field_or_the_query() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for (args, want) in [
            (
                a(&[
                    "api",
                    "graphql",
                    "-F",
                    "owner=akeylesslabs",
                    "-f",
                    "query=query($owner:String!){x}",
                ]),
                Some("akeylesslabs"),
            ),
            (
                a(&[
                    "api",
                    "graphql",
                    "--field=owner=pleme-io",
                    "-f",
                    "query={x}",
                ]),
                Some("pleme-io"),
            ),
            (
                a(&[
                    "api",
                    "graphql",
                    "-f",
                    r#"query=query{repository(owner:"akeylesslabs",name:"akeyless-environments"){id}}"#,
                ]),
                Some("akeylesslabs"),
            ),
            (
                a(&[
                    "api",
                    "graphql",
                    "-f",
                    r#"query={ repository(owner: "akeylesslabs", name: "x") { id } }"#,
                ]),
                Some("akeylesslabs"),
            ),
            (
                a(&[
                    "api",
                    "graphql",
                    "-f",
                    r#"query={ organization(login: "akeylesslabs") { id } }"#,
                ]),
                Some("akeylesslabs"),
            ),
            (
                a(&[
                    "api",
                    "graphql",
                    "-f",
                    r#"query={ repositoryOwner(login: "pleme-io") { id } }"#,
                ]),
                Some("pleme-io"),
            ),
        ] {
            assert_eq!(
                owner_from_graphql(&args, &graphql_owner_args(None)).as_deref(),
                want,
                "{args:?}"
            );
        }
    }

    #[test]
    fn graphql_owner_args_come_from_the_table() {
        let t =
            CredentialTable::from_json(r#"{"version":1,"owners":{},"graphqlOwnerArgs":["org"]}"#)
                .unwrap();
        let args = v(&[
            "api",
            "graphql",
            "-f",
            r#"query={ x(org: "akeylesslabs") { id } }"#,
        ]);
        assert_eq!(
            owner_from_graphql(&args, &graphql_owner_args(Some(&t))).as_deref(),
            Some("akeylesslabs")
        );
        let args = v(&[
            "api",
            "graphql",
            "-f",
            r#"query={ repository(owner: "akeylesslabs") { id } }"#,
        ]);
        assert_eq!(
            owner_from_graphql(&args, &graphql_owner_args(Some(&t))),
            None
        );
    }

    #[test]
    fn graphql_declines_without_a_literal_owner() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for args in [
            a(&["api", "graphql", "-f", "query=query{viewer{login}}"]),
            a(&[
                "api",
                "graphql",
                "-f",
                "query=query($owner:String!){repository(owner:$owner,name:\"x\"){id}}",
            ]),
            a(&["api", "graphql", "-F", "owner=$OWNER", "-f", "query={x}"]),
            a(&["api", "repos/akeylesslabs/x", "-f", "owner=pleme-io"]),
            a(&["pr", "view", "1", "-f", "owner=pleme-io"]),
        ] {
            assert_eq!(
                owner_from_graphql(&args, &graphql_owner_args(None)),
                None,
                "{args:?}"
            );
        }
    }

    #[test]
    fn api_path_declines_when_the_path_names_no_owner() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for args in [
            a(&["api", "user/packages/container/x"]),
            a(&["api", "repositories/1345230532"]),
            a(&["api", "search/code"]),
            // A template, not a real owner — must not resolve to a token.
            a(&["api", "repos/{owner}/{repo}"]),
            // Not an `api` invocation at all.
            a(&["pr", "view", "436"]),
            a(&["api"]),
        ] {
            assert_eq!(owner_from_api_path(&args), None, "{args:?}");
        }
    }

    #[test]
    fn gh_own_login_commands_route_to_gh_own_credentials() {
        // The regression: `gh auth refresh` through this wrapper refused with
        // "The value of the GITHUB_TOKEN environment variable is being used".
        for sub in OWN_CREDENTIAL_COMMANDS {
            assert_eq!(route(&v(&["auth", sub])), Route::OwnCredentials, "{sub}");
        }
        assert_eq!(
            route(&v(&[
                "auth",
                "refresh",
                "-h",
                "github.com",
                "-s",
                "admin:org"
            ])),
            Route::OwnCredentials
        );
        assert_eq!(route(&v(&["auth", "status"])), Route::Status);
        assert_eq!(route(&v(&["auth", "token"])), Route::Token);
    }

    #[test]
    fn everything_else_is_an_ordinary_call() {
        for args in [
            v(&["pr", "list"]),
            v(&["api", "repos/pleme-io/nix"]),
            // `auth` as an argument, not the command, is not gh's auth.
            v(&["repo", "view", "auth"]),
            v(&["auth"]),
            v(&["auth", "--help"]),
        ] {
            assert_eq!(route(&args), Route::Inject, "{args:?}");
        }
    }

    #[test]
    fn another_host_is_left_to_gh() {
        assert!(!names_another_host(&v(&["auth", "token"])));
        assert!(!names_another_host(&v(&[
            "auth",
            "token",
            "-h",
            "github.com"
        ])));
        assert!(names_another_host(&v(&[
            "auth",
            "token",
            "--hostname",
            "ghe.example.com"
        ])));
        assert!(names_another_host(&v(&[
            "auth",
            "token",
            "--hostname=ghe.example.com"
        ])));
    }

    #[test]
    fn a_route_row_names_the_sops_key_and_path_but_never_the_token() {
        let t = probe_table();
        let rows = route_rows(&t);
        assert_eq!(rows.len(), 1);
        let text = rows[0].to_string();
        assert!(text.contains("pleme-io"), "{text}");
        assert!(text.contains("sops key k"), "{text}");
        assert!(text.contains("/nope"), "{text}");
        // The probe table's token file does not exist.
        assert!(text.contains("MISSING"), "{text}");
    }

    /// The regression this function exists for: an `api` path must outrank the
    /// cwd, or a cross-org call silently uses the wrong token and reads as 404.
    #[test]
    fn api_path_outranks_the_cwd_but_not_an_explicit_repo_flag() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            determine_owner(&a(&["api", "repos/akeylesslabs/pitr-slack"]), None).as_deref(),
            Some("akeylesslabs")
        );
        assert_eq!(
            determine_owner(
                &a(&["api", "repos/akeylesslabs/x", "--repo", "pleme-io/y"]),
                None
            )
            .as_deref(),
            Some("pleme-io"),
            "an explicit --repo is the operator's stated intent and still wins"
        );
    }
}
