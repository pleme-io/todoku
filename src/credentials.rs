//! Owner-scoped GitHub credential resolution.
//!
//! # The defect this closes
//!
//! Every GitHub credential path in the pleme-io fleet is *process-global*: one
//! ambient token chosen by env-var precedence, with an optional single-file
//! fallback. Meanwhile `owner` is threaded through every API signature
//! (`get_repo_head(owner, repo)`). So the one fact that decides *which*
//! credential is correct is present at every call site and consulted at none of
//! them.
//!
//! That was survivable while one classic PAT could read every org. It stopped
//! being survivable when the fleet moved to **fine-grained** PATs, which are
//! bound to exactly ONE resource owner and answer `404` — not `403` — for any
//! other. A single global token is therefore no longer a credential; it is a
//! choice of which org to break.
//!
//! # The shape
//!
//! A table maps `owner` to the FILE its credential was materialized to. The
//! table carries no secret material — only owners and paths — which is why it
//! can be a plain rendered file rather than a secret, and why rotating a token
//! needs no re-render. The token is read at resolution time.
//!
//! # `Resolution` has four arms on purpose
//!
//! An answer must say WHICH of four things happened, and no two of them may
//! render the same way:
//!
//! - [`Resolution::Found`] — a usable credential.
//! - [`Resolution::UnknownOwner`] — the owner is absent from the table. This is
//!   a **finding, not an error**: anonymous is the correct way to reach a public
//!   repo, and an honest `404` is the correct answer for a private one. Rounding
//!   it up to a token would re-arm the bare-scope defect the nix side forbids.
//! - [`Resolution::Missing`] — declared but the file is absent. Almost always
//!   "declared in nix, not rebuilt yet".
//! - [`Resolution::Empty`] — declared, present, **zero bytes**.
//!
//! `Empty` exists because it was measured, not imagined:
//! `~/.config/github/drzln/token` was a 0-byte file for an unknown period. An
//! empty bearer token authenticates as nobody and GitHub answers
//! `401 Bad credentials` — indistinguishable from a revoked token, which is how
//! a five-minute diagnosis becomes an hour of hunting a rotation that never
//! happened. Collapsing `Empty` into `Found("")` reproduces exactly that.
//!
//! # Why a local token type
//!
//! `cofre_secret::Secret` is the fleet's redacting secret type and would be the
//! reuse-first choice, but `cofre-secret` is **not published to crates.io**
//! (checked 2026-08-24), and `todoku` is a published library. Depending on it
//! would mean a path dependency out of a released crate. [`Token`] is therefore
//! a local newtype whose only job is to keep the value out of `Debug` output.
//! If cofre-secret is ever published, this is the seam to replace.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The only table shape this build understands.
///
/// A consumer that does not recognise the version must REFUSE rather than
/// guess — a credential table read under the wrong schema resolves the wrong
/// owner to the wrong token, which is worse than not resolving at all.
pub const TABLE_VERSION: u32 = 1;

/// Environment variable naming an explicit table location, for tests and for
/// consumers that keep the table somewhere other than the default path.
pub const TABLE_PATH_ENV: &str = "GITHUB_CREDENTIAL_TABLE";

/// One owner's entry: where its credential was written, and the key it came
/// from (carried for diagnostics — it is what a human greps for in the nix).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OwnerEntry {
    /// Absolute path to the file holding the token.
    #[serde(rename = "tokenPath")]
    pub token_path: PathBuf,
    /// The `category/name` secret key that produced `token_path`.
    #[serde(rename = "sopsKey")]
    pub sops_key: String,
}

/// The owner → credential table.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CredentialTable {
    /// Table schema version; must equal [`TABLE_VERSION`].
    pub version: u32,
    /// Owners this table knows about, keyed by GitHub owner login.
    pub owners: BTreeMap<String, OwnerEntry>,
}

/// A resolved token. `Debug` is redacted; the value is reachable only via
/// [`Token::expose`], so it cannot reach a log by accident.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// The token text. Naming it `expose` rather than `get` is deliberate: the
    /// call site should read as a decision.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Length in bytes — safe to log, and enough to tell "empty" from "wrong".
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the token is empty. Cannot be true for a [`Token`] produced by
    /// [`CredentialTable::resolve`], which returns [`Resolution::Empty`]
    /// instead — this exists only for the `clippy::len_without_is_empty` pair.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token(<redacted {} bytes>)", self.0.len())
    }
}

/// What resolving an owner actually produced. See the module docs for why
/// there are four arms rather than an `Option`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A usable credential for `owner`.
    Found {
        /// The owner this credential authenticates.
        owner: String,
        /// The credential.
        token: Token,
    },
    /// `owner` is not in the table. Proceed ANONYMOUSLY — do not substitute
    /// another owner's token.
    UnknownOwner {
        /// The owner that was asked for.
        owner: String,
    },
    /// Declared in the table, but the file does not exist. Usually "not
    /// rebuilt yet".
    Missing {
        /// The owner that was asked for.
        owner: String,
        /// The path that was expected to hold the token.
        path: PathBuf,
    },
    /// Declared, present, and zero bytes (or whitespace only). Never returned
    /// as a token — see the module docs.
    Empty {
        /// The owner that was asked for.
        owner: String,
        /// The path that holds nothing.
        path: PathBuf,
    },
}

impl Resolution {
    /// The token, if this resolution produced one.
    #[must_use]
    pub fn token(&self) -> Option<&Token> {
        match self {
            Self::Found { token, .. } => Some(token),
            _ => None,
        }
    }

    /// Whether this resolution is a defect worth telling a human about.
    ///
    /// `UnknownOwner` is deliberately NOT a problem: anonymous access is the
    /// correct behaviour for an owner nobody declared.
    #[must_use]
    pub fn is_defect(&self) -> bool {
        matches!(self, Self::Missing { .. } | Self::Empty { .. })
    }
}

/// Why a table could not be read or understood.
#[derive(Debug)]
pub enum CredentialError {
    /// The table is not valid JSON, or does not match the expected shape.
    Parse {
        /// Where the table was read from.
        path: Option<PathBuf>,
        /// The underlying parse failure.
        detail: String,
    },
    /// The table declares a schema this build does not implement.
    UnsupportedVersion {
        /// The version the table claims.
        found: u32,
        /// The version this build understands.
        supported: u32,
    },
    /// The table itself could not be read.
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O failure.
        detail: String,
    },
    /// No table location could be determined.
    NoTablePath,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { path, detail } => match path {
                Some(p) => write!(
                    f,
                    "credential table at {} is malformed: {detail}",
                    p.display()
                ),
                None => write!(f, "credential table is malformed: {detail}"),
            },
            Self::UnsupportedVersion { found, supported } => write!(
                f,
                "credential table declares version {found}, this build understands {supported}; \
                 refusing to guess"
            ),
            Self::Io { path, detail } => {
                write!(
                    f,
                    "cannot read credential table {}: {detail}",
                    path.display()
                )
            }
            Self::NoTablePath => write!(
                f,
                "no credential table location: set {TABLE_PATH_ENV} or provide \
                 ~/.config/github/credentials.json"
            ),
        }
    }
}

impl std::error::Error for CredentialError {}

impl CredentialTable {
    /// Parse a table from JSON text.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Parse`] if the text is not the expected shape, and
    /// [`CredentialError::UnsupportedVersion`] if it declares a schema this
    /// build does not implement.
    pub fn from_json(text: &str) -> Result<Self, CredentialError> {
        let table: Self = serde_json::from_str(text).map_err(|e| CredentialError::Parse {
            path: None,
            detail: e.to_string(),
        })?;
        table.check_version()
    }

    /// Read a table from `path`.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Io`] if the file cannot be read, plus the errors of
    /// [`CredentialTable::from_json`].
    pub fn load(path: &Path) -> Result<Self, CredentialError> {
        let text = std::fs::read_to_string(path).map_err(|e| CredentialError::Io {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;
        let table: Self = serde_json::from_str(&text).map_err(|e| CredentialError::Parse {
            path: Some(path.to_path_buf()),
            detail: e.to_string(),
        })?;
        table.check_version()
    }

    fn check_version(self) -> Result<Self, CredentialError> {
        if self.version == TABLE_VERSION {
            Ok(self)
        } else {
            Err(CredentialError::UnsupportedVersion {
                found: self.version,
                supported: TABLE_VERSION,
            })
        }
    }

    /// Where the table lives by default: `$GITHUB_CREDENTIAL_TABLE`, else
    /// `$XDG_CONFIG_HOME/github/credentials.json`, else
    /// `$HOME/.config/github/credentials.json`.
    #[must_use]
    pub fn default_path() -> Option<PathBuf> {
        if let Some(explicit) = std::env::var_os(TABLE_PATH_ENV) {
            if !explicit.is_empty() {
                return Some(PathBuf::from(explicit));
            }
        }
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("github").join("credentials.json"))
    }

    /// Read the table from [`CredentialTable::default_path`].
    ///
    /// # Errors
    ///
    /// [`CredentialError::NoTablePath`] if no location can be determined, plus
    /// the errors of [`CredentialTable::load`].
    pub fn load_default() -> Result<Self, CredentialError> {
        let path = Self::default_path().ok_or(CredentialError::NoTablePath)?;
        Self::load(&path)
    }

    /// Resolve `owner` to a credential.
    ///
    /// Reading the token file is the only I/O, and a failure to read it is
    /// reported as [`Resolution::Missing`] rather than as an error: "this owner
    /// has no usable credential right now" is a normal answer that the caller
    /// must handle either way, and making it an `Err` would tempt callers into
    /// treating it as fatal when anonymous access may still be correct.
    #[must_use]
    pub fn resolve(&self, owner: &str) -> Resolution {
        let Some(entry) = self.owners.get(owner) else {
            return Resolution::UnknownOwner {
                owner: owner.to_string(),
            };
        };
        let Ok(raw) = std::fs::read_to_string(&entry.token_path) else {
            return Resolution::Missing {
                owner: owner.to_string(),
                path: entry.token_path.clone(),
            };
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Resolution::Empty {
                owner: owner.to_string(),
                path: entry.token_path.clone(),
            };
        }
        Resolution::Found {
            owner: owner.to_string(),
            token: Token(trimmed.to_string()),
        }
    }

    /// The owners this table declares.
    pub fn owners(&self) -> impl Iterator<Item = (&str, &OwnerEntry)> {
        self.owners.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// The owner half of an `owner/repo` argument, as `gh --repo` takes it.
///
/// Accepts a bare `owner/repo` and a full URL form, because `gh -R` accepts
/// both and a wrapper that rejected one would be a downgrade.
#[must_use]
pub fn owner_from_repo_arg(arg: &str) -> Option<&str> {
    let arg = arg.trim();
    if arg.is_empty() {
        return None;
    }
    if arg.contains("://") || arg.starts_with("git@") {
        return owner_from_remote_url(arg);
    }
    let mut parts = arg.split('/');
    let owner = parts.next()?;
    // `owner/repo` and nothing longer: a three-segment path is not a repo
    // argument, and silently taking its first segment would resolve a
    // credential for something the user did not name.
    parts.next()?;
    if parts.next().is_some() || owner.is_empty() {
        return None;
    }
    Some(owner)
}

/// The owner from a git remote URL — `git@github.com:owner/repo.git`,
/// `https://github.com/owner/repo`, or `ssh://git@github.com/owner/repo`.
///
/// Returns `None` for a non-GitHub host, deliberately: resolving a GitHub
/// credential for some other forge's URL is exactly the kind of
/// credential-crossing this module exists to prevent.
#[must_use]
pub fn owner_from_remote_url(url: &str) -> Option<&str> {
    let url = url.trim();
    let rest = if let Some(scp) = url.strip_prefix("git@") {
        // scp-like: git@github.com:owner/repo.git
        let (host, path) = scp.split_once(':')?;
        if !is_github_host(host) {
            return None;
        }
        path
    } else {
        let after_scheme = url.split_once("://").map_or(url, |(_, r)| r);
        // strip any userinfo (`git@`) that a URL form may carry
        let after_userinfo = after_scheme
            .split_once('@')
            .map_or(after_scheme, |(_, r)| r);
        let (host, path) = after_userinfo.split_once('/')?;
        if !is_github_host(host) {
            return None;
        }
        path
    };
    let owner = rest.trim_start_matches('/').split('/').next()?;
    if owner.is_empty() { None } else { Some(owner) }
}

fn is_github_host(host: &str) -> bool {
    // Drop a port if present; compare case-insensitively.
    let host = host.split(':').next().unwrap_or(host);
    host.eq_ignore_ascii_case("github.com") || host.eq_ignore_ascii_case("www.github.com")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn table_json(path: &str) -> String {
        format!(
            r#"{{"version":1,"owners":{{"pleme-io":{{"tokenPath":"{path}","sopsKey":"github/pleme-io/token"}}}}}}"#
        )
    }

    #[test]
    fn parses_the_rendered_shape() {
        // Byte-for-byte the shape `renderResolverTable` emits in
        // nix/lib/github-token-scopes.nix — keys camelCase, owners keyed by
        // login. If the nix renderer changes, this test is what fails.
        let json = r#"{"owners":{"akeylesslabs":{"sopsKey":"github/akeylesslabs/token","tokenPath":"/home/u/.config/github/akeylesslabs/token"},"pleme-io":{"sopsKey":"github/pleme-io/token","tokenPath":"/home/u/.config/github/pleme-io/token"}},"version":1}"#;
        let t = CredentialTable::from_json(json).expect("parses");
        assert_eq!(t.owners.len(), 2);
        assert_eq!(
            t.owners["akeylesslabs"].sops_key,
            "github/akeylesslabs/token"
        );
    }

    #[test]
    fn refuses_an_unknown_version_rather_than_guessing() {
        let json = r#"{"version":2,"owners":{}}"#;
        match CredentialTable::from_json(json) {
            Err(CredentialError::UnsupportedVersion { found, supported }) => {
                assert_eq!(found, 2);
                assert_eq!(supported, TABLE_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn unknown_owner_is_a_finding_not_a_defect() {
        let t = CredentialTable::from_json(&table_json("/nonexistent")).unwrap();
        let r = t.resolve("some-other-org");
        assert!(matches!(r, Resolution::UnknownOwner { .. }));
        assert!(!r.is_defect(), "anonymous access is correct here");
        assert!(r.token().is_none());
    }

    #[test]
    fn declared_but_absent_file_is_missing() {
        let t = CredentialTable::from_json(&table_json("/definitely/not/here")).unwrap();
        let r = t.resolve("pleme-io");
        assert!(matches!(r, Resolution::Missing { .. }));
        assert!(r.is_defect());
    }

    #[test]
    fn an_empty_token_file_is_empty_never_found() {
        // The measured trap: ~/.config/github/drzln/token was 0 bytes, and an
        // empty bearer token yields `401 Bad credentials` — identical to a
        // revoked one. This must never surface as Found("").
        let dir = std::env::temp_dir().join(format!("todoku-cred-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty-token");
        std::fs::write(&path, "   \n").unwrap();
        let t = CredentialTable::from_json(&table_json(&path.to_string_lossy())).unwrap();
        let r = t.resolve("pleme-io");
        assert!(matches!(r, Resolution::Empty { .. }), "got {r:?}");
        assert!(r.token().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn found_trims_the_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("todoku-cred-found-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        let mut f = std::fs::File::create(&path).unwrap();
        // A trailing newline is what every editor and every `echo >` leaves.
        // Sending it in an Authorization header is a malformed request.
        writeln!(f, "github_pat_example").unwrap();
        drop(f);
        let t = CredentialTable::from_json(&table_json(&path.to_string_lossy())).unwrap();
        match t.resolve("pleme-io") {
            Resolution::Found { token, owner } => {
                assert_eq!(owner, "pleme-io");
                assert_eq!(token.expose(), "github_pat_example");
            }
            other => panic!("expected Found, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn token_debug_is_redacted() {
        let t = Token("supersecret".to_string());
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("supersecret"), "leaked: {rendered}");
        assert!(rendered.contains("11 bytes"));
    }

    #[test]
    fn repo_arg_forms() {
        assert_eq!(owner_from_repo_arg("pleme-io/nix"), Some("pleme-io"));
        assert_eq!(
            owner_from_repo_arg("akeylesslabs/frontend-react"),
            Some("akeylesslabs")
        );
        assert_eq!(
            owner_from_repo_arg("https://github.com/pleme-io/nix"),
            Some("pleme-io")
        );
        // Not a repo argument: a bare owner, or a deeper path.
        assert_eq!(owner_from_repo_arg("pleme-io"), None);
        assert_eq!(owner_from_repo_arg("a/b/c"), None);
        assert_eq!(owner_from_repo_arg(""), None);
    }

    #[test]
    fn remote_url_forms() {
        assert_eq!(
            owner_from_remote_url("git@github.com:akeylesslabs/frontend-react.git"),
            Some("akeylesslabs")
        );
        assert_eq!(
            owner_from_remote_url("https://github.com/pleme-io/nix.git"),
            Some("pleme-io")
        );
        assert_eq!(
            owner_from_remote_url("ssh://git@github.com/pleme-io/nix"),
            Some("pleme-io")
        );
        assert_eq!(
            owner_from_remote_url("https://GitHub.com/pleme-io/nix"),
            Some("pleme-io")
        );
    }

    #[test]
    fn a_non_github_host_resolves_to_nothing() {
        // Handing a GitHub token to gitlab.com is the credential-crossing this
        // module exists to prevent; it must not be a near-miss match.
        assert_eq!(owner_from_remote_url("git@gitlab.com:org/repo.git"), None);
        assert_eq!(owner_from_remote_url("https://gitlab.com/org/repo"), None);
        // Nor a lookalike host that merely ends in the right string.
        assert_eq!(
            owner_from_remote_url("https://notgithub.com/org/repo"),
            None
        );
    }
}
