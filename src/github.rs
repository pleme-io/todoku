//! GitHub API client built on todoku's `HttpClient`.

use crate::auth::BearerToken;
use crate::client::HttpClient;
use crate::error::TodokuError;
use serde::Deserialize;

/// Trait abstracting GitHub API interactions for testability.
#[async_trait::async_trait]
pub trait GitHubApi: Send + Sync {
    /// Get the HEAD commit SHA for a repo's default branch.
    async fn get_repo_head(&self, owner: &str, repo: &str) -> Result<String, TodokuError>;

    /// Get the latest tag for a repo (returns None if no tags).
    async fn get_latest_tag(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Option<String>, TodokuError>;

    /// Detect the primary language of a repo.
    async fn get_primary_language(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Option<String>, TodokuError>;

    /// List repos for an org or user.
    async fn list_repos(
        &self,
        owner: &str,
        owner_type: OwnerType,
    ) -> Result<Vec<GitHubRepo>, TodokuError>;

    /// Get file metadata (SHA, size, download URL).
    async fn get_file_info(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<FileInfo, TodokuError>;
}

/// Whether the owner is an organization or a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerType {
    /// GitHub organization.
    Org,
    /// GitHub user account.
    User,
}

/// Summary of a GitHub repository.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubRepo {
    /// Repository name (e.g. "todoku").
    pub name: String,
    /// Full name including owner (e.g. "pleme-io/todoku").
    #[serde(default)]
    pub full_name: String,
    /// Default branch name (e.g. "main").
    #[serde(default)]
    pub default_branch: Option<String>,
    /// Primary language detected by GitHub.
    #[serde(default)]
    pub language: Option<String>,
    /// Whether the repository is archived.
    #[serde(default)]
    pub archived: bool,
    /// Whether the repository is a fork.
    #[serde(default)]
    pub fork: bool,
}

/// Metadata about a file in a GitHub repository.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Git blob SHA.
    pub sha: String,
    /// File size in bytes.
    pub size: u64,
    /// Raw download URL.
    pub download_url: String,
}

#[derive(Debug, Deserialize)]
struct BranchRef {
    object: GitObject,
}

#[derive(Debug, Deserialize)]
struct GitObject {
    sha: String,
}

#[derive(Debug, Deserialize)]
struct TagEntry {
    name: String,
}

#[derive(Debug, Deserialize)]
struct ContentEntry {
    sha: String,
    size: u64,
    download_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RepoInfo {
    default_branch: Option<String>,
    language: Option<String>,
}

/// GitHub API client using todoku's `HttpClient`.
pub struct GitHubClient {
    client: HttpClient,
}

impl GitHubClient {
    /// Create a new GitHub client with optional token.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` if the underlying HTTP client fails to build.
    pub fn new(token: Option<&str>) -> Result<Self, TodokuError> {
        let mut builder = HttpClient::builder()
            .base_url("https://api.github.com")
            .header(reqwest::header::ACCEPT, "application/vnd.github.v3+json");

        if let Some(t) = token {
            builder = builder.auth(BearerToken::new(t));
        }

        Ok(Self {
            client: builder.build()?,
        })
    }

    /// Create from an existing `HttpClient` (for custom configuration).
    #[must_use]
    pub fn from_client(client: HttpClient) -> Self {
        Self { client }
    }

    /// Create from the `GITHUB_TOKEN` environment variable.
    ///
    /// # Errors
    ///
    /// Returns `TodokuError` if the underlying HTTP client fails to build.
    pub fn from_env() -> Result<Self, TodokuError> {
        let token = std::env::var("GITHUB_TOKEN").ok();
        Self::new(token.as_deref())
    }
}

#[async_trait::async_trait]
impl GitHubApi for GitHubClient {
    async fn get_repo_head(&self, owner: &str, repo: &str) -> Result<String, TodokuError> {
        let info: RepoInfo = self.client.get(&format!("/repos/{owner}/{repo}")).await?;
        let branch = info.default_branch.unwrap_or_else(|| "main".to_string());
        let branch_ref: BranchRef = self
            .client
            .get(&format!("/repos/{owner}/{repo}/git/ref/heads/{branch}"))
            .await?;
        Ok(branch_ref.object.sha)
    }

    async fn get_latest_tag(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Option<String>, TodokuError> {
        let tags: Vec<TagEntry> = self
            .client
            .get(&format!("/repos/{owner}/{repo}/tags?per_page=1"))
            .await?;
        Ok(tags.into_iter().next().map(|t| t.name))
    }

    async fn get_primary_language(
        &self,
        owner: &str,
        repo: &str,
    ) -> Result<Option<String>, TodokuError> {
        let info: RepoInfo = self.client.get(&format!("/repos/{owner}/{repo}")).await?;
        Ok(info.language)
    }

    async fn list_repos(
        &self,
        owner: &str,
        owner_type: OwnerType,
    ) -> Result<Vec<GitHubRepo>, TodokuError> {
        // GitHub caps `per_page` at 100. Paginate until a short page is returned.
        const PER_PAGE: u32 = 100;
        let base = match owner_type {
            OwnerType::Org => format!("/orgs/{owner}/repos"),
            OwnerType::User => format!("/users/{owner}/repos"),
        };
        let mut all = Vec::new();
        let mut page: u32 = 1;
        loop {
            let path = format!("{base}?per_page={PER_PAGE}&type=all&page={page}");
            let mut batch: Vec<GitHubRepo> = self.client.get(&path).await?;
            let len = batch.len();
            all.append(&mut batch);
            if len < PER_PAGE as usize {
                break;
            }
            page += 1;
        }
        Ok(all)
    }

    async fn get_file_info(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<FileInfo, TodokuError> {
        let entry: ContentEntry = self
            .client
            .get(&format!("/repos/{owner}/{repo}/contents/{path}"))
            .await?;
        Ok(FileInfo {
            sha: entry.sha,
            size: entry.size,
            download_url: entry.download_url.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GitHubClient construction ---

    #[test]
    fn new_without_token() {
        let client = GitHubClient::new(None);
        assert!(client.is_ok());
    }

    #[test]
    fn new_with_token() {
        let client = GitHubClient::new(Some("ghp_test123"));
        assert!(client.is_ok());
    }

    #[test]
    fn new_with_empty_token() {
        let client = GitHubClient::new(Some(""));
        assert!(client.is_ok());
    }

    #[test]
    fn from_env_succeeds() {
        // from_env always succeeds (None token if env var missing)
        let client = GitHubClient::from_env();
        assert!(client.is_ok());
    }

    #[test]
    fn from_env_reads_github_token() {
        // SAFETY: this test runs in a single thread and no other code
        // concurrently reads GITHUB_TOKEN during this test.
        unsafe {
            std::env::set_var("GITHUB_TOKEN", "ghp_env_test_token");
        }
        let client = GitHubClient::from_env();
        assert!(client.is_ok());
        unsafe {
            std::env::remove_var("GITHUB_TOKEN");
        }
    }

    #[test]
    fn from_client_custom() {
        let http = HttpClient::builder()
            .base_url("https://github.example.com/api/v3")
            .auth(BearerToken::new("enterprise-token"))
            .build()
            .unwrap();
        let _gh = GitHubClient::from_client(http);
    }

    // --- GitHubRepo deserialization ---

    #[test]
    fn deserialize_full_repo() {
        let json = r#"{
            "name": "todoku",
            "full_name": "pleme-io/todoku",
            "default_branch": "main",
            "language": "Rust",
            "archived": false,
            "fork": false
        }"#;
        let repo: GitHubRepo = serde_json::from_str(json).unwrap();
        assert_eq!(repo.name, "todoku");
        assert_eq!(repo.full_name, "pleme-io/todoku");
        assert_eq!(repo.default_branch.as_deref(), Some("main"));
        assert_eq!(repo.language.as_deref(), Some("Rust"));
        assert!(!repo.archived);
        assert!(!repo.fork);
    }

    #[test]
    fn deserialize_minimal_repo() {
        let json = r#"{"name": "minimal"}"#;
        let repo: GitHubRepo = serde_json::from_str(json).unwrap();
        assert_eq!(repo.name, "minimal");
        assert_eq!(repo.full_name, "");
        assert!(repo.default_branch.is_none());
        assert!(repo.language.is_none());
        assert!(!repo.archived);
        assert!(!repo.fork);
    }

    #[test]
    fn deserialize_archived_fork_repo() {
        let json = r#"{
            "name": "old-fork",
            "full_name": "user/old-fork",
            "archived": true,
            "fork": true
        }"#;
        let repo: GitHubRepo = serde_json::from_str(json).unwrap();
        assert_eq!(repo.name, "old-fork");
        assert!(repo.archived);
        assert!(repo.fork);
    }

    #[test]
    fn deserialize_repo_null_language() {
        let json = r#"{
            "name": "empty-repo",
            "full_name": "user/empty-repo",
            "language": null,
            "default_branch": "main"
        }"#;
        let repo: GitHubRepo = serde_json::from_str(json).unwrap();
        assert!(repo.language.is_none());
        assert_eq!(repo.default_branch.as_deref(), Some("main"));
    }

    #[test]
    fn deserialize_repo_with_extra_fields() {
        // GitHub API returns many more fields -- serde should ignore unknown fields
        let json = r#"{
            "name": "todoku",
            "full_name": "pleme-io/todoku",
            "id": 123456,
            "private": false,
            "html_url": "https://github.com/pleme-io/todoku",
            "description": "HTTP client",
            "topics": ["rust", "http"]
        }"#;
        let repo: GitHubRepo = serde_json::from_str(json).unwrap();
        assert_eq!(repo.name, "todoku");
        assert_eq!(repo.full_name, "pleme-io/todoku");
    }

    #[test]
    fn deserialize_repo_list() {
        let json = r#"[
            {"name": "repo1", "full_name": "org/repo1"},
            {"name": "repo2", "full_name": "org/repo2", "language": "Go"},
            {"name": "repo3", "full_name": "org/repo3", "archived": true}
        ]"#;
        let repos: Vec<GitHubRepo> = serde_json::from_str(json).unwrap();
        assert_eq!(repos.len(), 3);
        assert_eq!(repos[0].name, "repo1");
        assert_eq!(repos[1].language.as_deref(), Some("Go"));
        assert!(repos[2].archived);
    }

    #[test]
    fn deserialize_empty_repo_list() {
        let json = "[]";
        let repos: Vec<GitHubRepo> = serde_json::from_str(json).unwrap();
        assert!(repos.is_empty());
    }

    // --- FileInfo ---

    #[test]
    fn file_info_construction() {
        let info = FileInfo {
            sha: "abc123".to_string(),
            size: 1024,
            download_url: "https://raw.githubusercontent.com/org/repo/main/file.txt".to_string(),
        };
        assert_eq!(info.sha, "abc123");
        assert_eq!(info.size, 1024);
        assert!(info.download_url.contains("raw.githubusercontent.com"));
    }

    #[test]
    fn file_info_clone() {
        let info = FileInfo {
            sha: "def456".to_string(),
            size: 2048,
            download_url: "https://example.com/file".to_string(),
        };
        let cloned = info.clone();
        assert_eq!(cloned.sha, info.sha);
        assert_eq!(cloned.size, info.size);
        assert_eq!(cloned.download_url, info.download_url);
    }

    #[test]
    fn file_info_debug() {
        let info = FileInfo {
            sha: "abc".to_string(),
            size: 42,
            download_url: String::new(),
        };
        let debug = format!("{info:?}");
        assert!(debug.contains("FileInfo"));
        assert!(debug.contains("abc"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn file_info_empty_download_url() {
        let info = FileInfo {
            sha: "sha256".to_string(),
            size: 0,
            download_url: String::new(),
        };
        assert!(info.download_url.is_empty());
        assert_eq!(info.size, 0);
    }

    // --- OwnerType ---

    #[test]
    fn owner_type_equality() {
        assert_eq!(OwnerType::Org, OwnerType::Org);
        assert_eq!(OwnerType::User, OwnerType::User);
        assert_ne!(OwnerType::Org, OwnerType::User);
    }

    #[test]
    fn owner_type_clone() {
        let ot = OwnerType::Org;
        let cloned = ot;
        assert_eq!(cloned, OwnerType::Org);
    }

    #[test]
    fn owner_type_debug() {
        let debug = format!("{:?}", OwnerType::Org);
        assert_eq!(debug, "Org");
        let debug = format!("{:?}", OwnerType::User);
        assert_eq!(debug, "User");
    }

    // --- Internal deserialization types ---

    #[test]
    fn deserialize_branch_ref() {
        let json = r#"{"ref": "refs/heads/main", "object": {"sha": "abc123", "type": "commit"}}"#;
        let br: BranchRef = serde_json::from_str(json).unwrap();
        assert_eq!(br.object.sha, "abc123");
    }

    #[test]
    fn deserialize_tag_entry() {
        let json = r#"{"name": "v1.2.3", "commit": {"sha": "xyz"}, "zipball_url": ""}"#;
        let tag: TagEntry = serde_json::from_str(json).unwrap();
        assert_eq!(tag.name, "v1.2.3");
    }

    #[test]
    fn deserialize_content_entry_with_download_url() {
        let json = r#"{
            "sha": "abc",
            "size": 512,
            "download_url": "https://raw.githubusercontent.com/o/r/main/f.txt",
            "name": "f.txt",
            "path": "f.txt",
            "type": "file"
        }"#;
        let entry: ContentEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.sha, "abc");
        assert_eq!(entry.size, 512);
        assert_eq!(
            entry.download_url.as_deref(),
            Some("https://raw.githubusercontent.com/o/r/main/f.txt")
        );
    }

    #[test]
    fn deserialize_content_entry_null_download_url() {
        let json = r#"{"sha": "def", "size": 0, "download_url": null}"#;
        let entry: ContentEntry = serde_json::from_str(json).unwrap();
        assert!(entry.download_url.is_none());
    }

    #[test]
    fn deserialize_repo_info() {
        let json = r#"{"default_branch": "develop", "language": "TypeScript", "id": 1}"#;
        let info: RepoInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.default_branch.as_deref(), Some("develop"));
        assert_eq!(info.language.as_deref(), Some("TypeScript"));
    }

    #[test]
    fn deserialize_repo_info_nulls() {
        let json = r#"{"default_branch": null, "language": null}"#;
        let info: RepoInfo = serde_json::from_str(json).unwrap();
        assert!(info.default_branch.is_none());
        assert!(info.language.is_none());
    }

    // --- Mock trait implementation ---

    struct MockGitHubApi {
        head_sha: String,
        latest_tag: Option<String>,
        language: Option<String>,
        repos: Vec<GitHubRepo>,
        file: FileInfo,
    }

    impl MockGitHubApi {
        fn new() -> Self {
            Self {
                head_sha: "mock_sha_abc123".to_string(),
                latest_tag: Some("v1.0.0".to_string()),
                language: Some("Rust".to_string()),
                repos: vec![GitHubRepo {
                    name: "mock-repo".to_string(),
                    full_name: "mock-org/mock-repo".to_string(),
                    default_branch: Some("main".to_string()),
                    language: Some("Rust".to_string()),
                    archived: false,
                    fork: false,
                }],
                file: FileInfo {
                    sha: "file_sha_456".to_string(),
                    size: 256,
                    download_url: "https://example.com/file.rs".to_string(),
                },
            }
        }
    }

    #[async_trait::async_trait]
    impl GitHubApi for MockGitHubApi {
        async fn get_repo_head(&self, _owner: &str, _repo: &str) -> Result<String, TodokuError> {
            Ok(self.head_sha.clone())
        }

        async fn get_latest_tag(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> Result<Option<String>, TodokuError> {
            Ok(self.latest_tag.clone())
        }

        async fn get_primary_language(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> Result<Option<String>, TodokuError> {
            Ok(self.language.clone())
        }

        async fn list_repos(
            &self,
            _owner: &str,
            _owner_type: OwnerType,
        ) -> Result<Vec<GitHubRepo>, TodokuError> {
            Ok(self.repos.clone())
        }

        async fn get_file_info(
            &self,
            _owner: &str,
            _repo: &str,
            _path: &str,
        ) -> Result<FileInfo, TodokuError> {
            Ok(self.file.clone())
        }
    }

    #[tokio::test]
    async fn mock_get_repo_head() {
        let mock = MockGitHubApi::new();
        let sha = mock.get_repo_head("pleme-io", "todoku").await.unwrap();
        assert_eq!(sha, "mock_sha_abc123");
    }

    #[tokio::test]
    async fn mock_get_latest_tag() {
        let mock = MockGitHubApi::new();
        let tag = mock.get_latest_tag("pleme-io", "todoku").await.unwrap();
        assert_eq!(tag, Some("v1.0.0".to_string()));
    }

    #[tokio::test]
    async fn mock_get_latest_tag_none() {
        let mut mock = MockGitHubApi::new();
        mock.latest_tag = None;
        let tag = mock.get_latest_tag("pleme-io", "todoku").await.unwrap();
        assert!(tag.is_none());
    }

    #[tokio::test]
    async fn mock_get_primary_language() {
        let mock = MockGitHubApi::new();
        let lang = mock
            .get_primary_language("pleme-io", "todoku")
            .await
            .unwrap();
        assert_eq!(lang, Some("Rust".to_string()));
    }

    #[tokio::test]
    async fn mock_get_primary_language_none() {
        let mut mock = MockGitHubApi::new();
        mock.language = None;
        let lang = mock
            .get_primary_language("pleme-io", "todoku")
            .await
            .unwrap();
        assert!(lang.is_none());
    }

    #[tokio::test]
    async fn mock_list_repos_org() {
        let mock = MockGitHubApi::new();
        let repos = mock.list_repos("pleme-io", OwnerType::Org).await.unwrap();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].name, "mock-repo");
    }

    #[tokio::test]
    async fn mock_list_repos_user() {
        let mock = MockGitHubApi::new();
        let repos = mock.list_repos("drzln", OwnerType::User).await.unwrap();
        assert_eq!(repos.len(), 1);
    }

    #[tokio::test]
    async fn mock_list_repos_empty() {
        let mut mock = MockGitHubApi::new();
        mock.repos = vec![];
        let repos = mock.list_repos("empty-org", OwnerType::Org).await.unwrap();
        assert!(repos.is_empty());
    }

    #[tokio::test]
    async fn mock_get_file_info() {
        let mock = MockGitHubApi::new();
        let info = mock
            .get_file_info("pleme-io", "todoku", "Cargo.toml")
            .await
            .unwrap();
        assert_eq!(info.sha, "file_sha_456");
        assert_eq!(info.size, 256);
        assert_eq!(info.download_url, "https://example.com/file.rs");
    }

    // --- Trait object usage ---

    #[tokio::test]
    async fn trait_object_dispatch() {
        let api: Box<dyn GitHubApi> = Box::new(MockGitHubApi::new());
        let sha = api.get_repo_head("org", "repo").await.unwrap();
        assert_eq!(sha, "mock_sha_abc123");
        let tag = api.get_latest_tag("org", "repo").await.unwrap();
        assert_eq!(tag, Some("v1.0.0".to_string()));
    }

    #[tokio::test]
    async fn arc_trait_object_dispatch() {
        let api: std::sync::Arc<dyn GitHubApi> = std::sync::Arc::new(MockGitHubApi::new());
        let repos = api.list_repos("org", OwnerType::Org).await.unwrap();
        assert_eq!(repos.len(), 1);
    }

    // --- GitHubRepo Clone + Debug ---

    #[test]
    fn github_repo_clone() {
        let repo = GitHubRepo {
            name: "test".to_string(),
            full_name: "org/test".to_string(),
            default_branch: Some("main".to_string()),
            language: Some("Rust".to_string()),
            archived: false,
            fork: true,
        };
        let cloned = repo.clone();
        assert_eq!(cloned.name, "test");
        assert_eq!(cloned.full_name, "org/test");
        assert!(cloned.fork);
    }

    #[test]
    fn github_repo_debug() {
        let repo = GitHubRepo {
            name: "debug-test".to_string(),
            full_name: String::new(),
            default_branch: None,
            language: None,
            archived: false,
            fork: false,
        };
        let debug = format!("{repo:?}");
        assert!(debug.contains("GitHubRepo"));
        assert!(debug.contains("debug-test"));
    }
}
