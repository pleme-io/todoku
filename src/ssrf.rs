//! SSRF (Server-Side Request Forgery) protection — a typed, pure-Rust guard.
//!
//! This is the pleme-io absorption of Obscura's SSRF protection: Obscura ships
//! a custom resolver that rejects requests aimed at private / forbidden IP
//! ranges (cloud metadata `169.254.169.254`, loopback, RFC1918, link-local,
//! CGNAT, ULA, etc.). Here the same intent is a typed classifier:
//! [`classify_ip`] maps an [`IpAddr`] to the [`SsrfReason`] that forbids it (or
//! `None` when the address is a legitimate public target), and [`check_url`]
//! lifts that to a [`url::Url`] — rejecting non-http(s) schemes, missing hosts,
//! and IP-literal hosts that [`classify_ip`] flags.
//!
//! The reason a *typed classifier* beats Obscura's resolver swap: the forbidden
//! set is enumerated once as a closed [`SsrfReason`] enum, every range maps to
//! exactly one variant, and a caller can match on the reason exhaustively. The
//! highest-value SSRF vector — cloud metadata endpoints — are IP literals
//! (`169.254.169.254`, `fd00:ec2::254`), which the synchronous [`check_url`]
//! path covers by parsing alone. [`check_url_resolved`] adds the **DNS-time**
//! parity with Obscura's resolver: it resolves a hostname host and runs
//! [`classify_ip`] on every resolved address, blocking the whole URL if any is
//! forbidden (so `metadata.google.internal` → `169.254.169.254` is caught, and
//! a rebinding host is refused outright). The one residual gap is the connector
//! re-resolving at connect time (TOCTOU); fully closing it means hooking
//! reqwest's `dns::Resolve` — the documented next step.
//!
//! Wired into [`crate::HttpClient`] behind the opt-in `ssrf_guard` flag (off by
//! default to preserve existing behavior); when on, every request runs
//! [`check_url`] on the resolved URL before sending and returns
//! [`crate::TodokuError::Ssrf`] on a forbidden target.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why a target address / URL is forbidden as an SSRF risk.
///
/// Each variant names exactly one forbidden class. The set is closed: every
/// range [`classify_ip`] rejects maps to one of these, so a caller can match
/// exhaustively on the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SsrfReason {
    /// Loopback (`127.0.0.0/8`, `::1`).
    Loopback,
    /// RFC1918 private IPv4 (`10/8`, `172.16/12`, `192.168/16`).
    Private,
    /// Link-local (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,
    /// Carrier-grade NAT shared address space (`100.64.0.0/10`).
    CgNat,
    /// IPv6 unique-local address (`fc00::/7`).
    UniqueLocal,
    /// Multicast (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// Unspecified address (`0.0.0.0`, `::`).
    Unspecified,
    /// A cloud instance metadata endpoint (`169.254.169.254`, `fd00:ec2::254`).
    ///
    /// Classified separately from [`Self::LinkLocal`] because it is the
    /// single highest-value SSRF target — the credential-leaking endpoint on
    /// AWS / GCP / Azure / Oracle / Alibaba.
    CloudMetadata,
    /// The URL scheme is not `http` or `https`.
    NonHttpScheme,
    /// The URL has no host component.
    NoHost,
}

impl SsrfReason {
    /// Stable lowercase identifier (used in errors + logs).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link-local",
            Self::CgNat => "cgnat",
            Self::UniqueLocal => "unique-local",
            Self::Multicast => "multicast",
            Self::Unspecified => "unspecified",
            Self::CloudMetadata => "cloud-metadata",
            Self::NonHttpScheme => "non-http-scheme",
            Self::NoHost => "no-host",
        }
    }

    /// Human-readable description of why the target is forbidden.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            Self::Loopback => "loopback address",
            Self::Private => "private (RFC1918) address",
            Self::LinkLocal => "link-local address",
            Self::CgNat => "carrier-grade NAT (CGNAT) address",
            Self::UniqueLocal => "IPv6 unique-local address",
            Self::Multicast => "multicast address",
            Self::Unspecified => "unspecified address",
            Self::CloudMetadata => "cloud instance metadata endpoint",
            Self::NonHttpScheme => "non-http(s) URL scheme",
            Self::NoHost => "URL has no host",
        }
    }
}

impl fmt::Display for SsrfReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

/// The IPv4 cloud-metadata literal (`169.254.169.254`) used fleet-wide by
/// AWS, GCP, Azure, Oracle, Alibaba, and DigitalOcean.
const CLOUD_METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// The IPv6 cloud-metadata literal (`fd00:ec2::254`) AWS exposes for IMDS.
const CLOUD_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// Classify an IP address, returning the [`SsrfReason`] that forbids it as a
/// request target — or `None` if it is a legitimate public address.
///
/// Covers both IPv4 and IPv6. Cloud-metadata literals are checked first so they
/// report [`SsrfReason::CloudMetadata`] rather than the broader
/// [`SsrfReason::LinkLocal`] / [`SsrfReason::UniqueLocal`] class they sit in.
#[must_use]
pub fn classify_ip(ip: IpAddr) -> Option<SsrfReason> {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

/// Classify an IPv4 address. See [`classify_ip`].
#[must_use]
fn classify_ipv4(ip: Ipv4Addr) -> Option<SsrfReason> {
    // Cloud metadata first: it is a link-local literal but the more specific,
    // more dangerous reason.
    if ip == CLOUD_METADATA_V4 {
        return Some(SsrfReason::CloudMetadata);
    }
    if ip.is_unspecified() {
        return Some(SsrfReason::Unspecified);
    }
    if ip.is_loopback() {
        return Some(SsrfReason::Loopback);
    }
    if ip.is_private() {
        return Some(SsrfReason::Private);
    }
    if ip.is_link_local() {
        return Some(SsrfReason::LinkLocal);
    }
    // CGNAT shared address space: 100.64.0.0/10 (RFC 6598). `Ipv4Addr::is_shared`
    // is unstable, so test the /10 prefix explicitly to stay on stable Rust.
    if is_cgnat_v4(ip) {
        return Some(SsrfReason::CgNat);
    }
    if ip.is_multicast() {
        return Some(SsrfReason::Multicast);
    }
    None
}

/// Classify an IPv6 address. See [`classify_ip`].
#[must_use]
fn classify_ipv6(ip: Ipv6Addr) -> Option<SsrfReason> {
    // Cloud metadata first (AWS IMDS over IPv6 is fd00:ec2::254, a ULA literal).
    if ip == CLOUD_METADATA_V6 {
        return Some(SsrfReason::CloudMetadata);
    }
    if ip.is_unspecified() {
        return Some(SsrfReason::Unspecified);
    }
    if ip.is_loopback() {
        return Some(SsrfReason::Loopback);
    }
    // Unique-local fc00::/7 (RFC 4193). `Ipv6Addr::is_unique_local` is unstable,
    // so test the /7 prefix explicitly to stay on stable Rust.
    if is_unique_local_v6(ip) {
        return Some(SsrfReason::UniqueLocal);
    }
    // Link-local fe80::/10. `Ipv6Addr::is_unicast_link_local` is unstable; test
    // the /10 prefix explicitly.
    if is_link_local_v6(ip) {
        return Some(SsrfReason::LinkLocal);
    }
    if ip.is_multicast() {
        return Some(SsrfReason::Multicast);
    }
    // An IPv4-mapped or IPv4-compatible IPv6 address must be classified as its
    // embedded IPv4 — otherwise `::ffff:127.0.0.1` would bypass the guard.
    if let Some(v4) = ip.to_ipv4() {
        return classify_ipv4(v4);
    }
    None
}

/// Whether `ip` is in the CGNAT shared range `100.64.0.0/10` (RFC 6598).
#[must_use]
fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 100.64.0.0/10 -> first octet 100, second octet top six bits 010000xx
    o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000
}

/// Whether `ip` is in the IPv6 unique-local range `fc00::/7` (RFC 4193).
#[must_use]
fn is_unique_local_v6(ip: Ipv6Addr) -> bool {
    // fc00::/7 -> first 7 bits are 1111110, i.e. first octet 0xfc..0xfd.
    (ip.octets()[0] & 0b1111_1110) == 0xfc
}

/// Whether `ip` is in the IPv6 link-local range `fe80::/10`.
#[must_use]
fn is_link_local_v6(ip: Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    // fe80::/10 -> top 10 bits are 1111111010.
    (seg0 & 0xffc0) == 0xfe80
}

/// Check a URL against the SSRF policy.
///
/// Rejects:
/// - non-`http`/`https` schemes ([`SsrfReason::NonHttpScheme`]),
/// - missing hosts ([`SsrfReason::NoHost`]),
/// - IP-literal hosts that [`classify_ip`] flags (the relevant range reason).
///
/// A hostname host (e.g. `api.example.com`) passes here; resolving it to an IP
/// and re-checking at DNS time is a documented follow-up. The IP-literal path
/// covers the highest-value SSRF vector — metadata endpoints are IP literals.
///
/// # Errors
///
/// Returns the [`SsrfReason`] that forbids the URL.
pub fn check_url(url: &url::Url) -> Result<(), SsrfReason> {
    match url.scheme() {
        "http" | "https" => {}
        _ => return Err(SsrfReason::NonHttpScheme),
    }

    let host = url.host().ok_or(SsrfReason::NoHost)?;

    match host {
        url::Host::Ipv4(v4) => {
            if let Some(reason) = classify_ip(IpAddr::V4(v4)) {
                return Err(reason);
            }
        }
        url::Host::Ipv6(v6) => {
            if let Some(reason) = classify_ip(IpAddr::V6(v6)) {
                return Err(reason);
            }
        }
        // A registered name (hostname). The synchronous path can't resolve it;
        // [`check_url_resolved`] does the DNS-time check. A hostname that is
        // actually an IP literal string is parsed into the Ipv4/Ipv6 arms above
        // by `url`, so the literal vector is covered here regardless.
        url::Host::Domain(_) => {}
    }

    Ok(())
}

/// Check a URL against the SSRF policy **including DNS-time resolution** — the
/// resolver-level parity with Obscura's custom resolver.
///
/// Runs the synchronous [`check_url`] checks first (scheme, no-host, IP
/// literals), then, for a registered-name host, resolves it via
/// `tokio::net::lookup_host` and runs [`classify_ip`] on **every** resolved
/// address. If *any* resolved address is forbidden the whole URL is rejected —
/// so a hostname that resolves to a private IP (`metadata.google.internal` →
/// `169.254.169.254`) is blocked, and a DNS-rebinding host that mixes
/// public+forbidden addresses is refused outright rather than gambled on.
///
/// A resolution *failure* is not an SSRF risk: it passes here, letting the
/// transport surface the real connection error instead of masking it.
///
/// Note the residual TOCTOU window — the connector re-resolves at connect time,
/// so a sub-TTL rebind could still differ. Closing that fully requires hooking
/// the connector's own resolver (`reqwest`'s `dns::Resolve`); this pre-flight
/// re-check is the high-value, low-complexity 90% and the documented next step
/// is the connector hook.
///
/// # Errors
///
/// Returns the [`SsrfReason`] that forbids the URL.
pub async fn check_url_resolved(url: &url::Url) -> Result<(), SsrfReason> {
    check_url(url)?;

    if let Some(url::Host::Domain(name)) = url.host() {
        let port = url.port_or_known_default().unwrap_or(0);
        if let Ok(addrs) = tokio::net::lookup_host((name, port)).await {
            for addr in addrs {
                if let Some(reason) = classify_ip(addr.ip()) {
                    return Err(reason);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    // --- cloud metadata (the highest-value vector) ---

    #[test]
    fn metadata_v4_is_cloud_metadata() {
        assert_eq!(
            classify_ip(ip("169.254.169.254")),
            Some(SsrfReason::CloudMetadata)
        );
    }

    #[test]
    fn metadata_v6_is_cloud_metadata() {
        assert_eq!(
            classify_ip(ip("fd00:ec2::254")),
            Some(SsrfReason::CloudMetadata)
        );
    }

    #[test]
    fn other_link_local_is_link_local_not_metadata() {
        assert_eq!(classify_ip(ip("169.254.1.1")), Some(SsrfReason::LinkLocal));
    }

    // --- loopback ---

    #[test]
    fn loopback_v4_blocked() {
        assert_eq!(classify_ip(ip("127.0.0.1")), Some(SsrfReason::Loopback));
    }

    #[test]
    fn loopback_v4_whole_range() {
        assert_eq!(classify_ip(ip("127.255.255.254")), Some(SsrfReason::Loopback));
    }

    #[test]
    fn loopback_v6_blocked() {
        assert_eq!(classify_ip(ip("::1")), Some(SsrfReason::Loopback));
    }

    // --- private (RFC1918) ---

    #[test]
    fn private_10_blocked() {
        assert_eq!(classify_ip(ip("10.0.0.1")), Some(SsrfReason::Private));
    }

    #[test]
    fn private_10_high() {
        assert_eq!(classify_ip(ip("10.255.255.255")), Some(SsrfReason::Private));
    }

    #[test]
    fn private_172_blocked() {
        assert_eq!(classify_ip(ip("172.16.0.1")), Some(SsrfReason::Private));
        assert_eq!(classify_ip(ip("172.31.255.255")), Some(SsrfReason::Private));
    }

    #[test]
    fn private_192_168_blocked() {
        assert_eq!(classify_ip(ip("192.168.1.1")), Some(SsrfReason::Private));
    }

    #[test]
    fn private_172_15_is_public() {
        // 172.15 is below the 172.16/12 range -> public.
        assert_eq!(classify_ip(ip("172.15.0.1")), None);
    }

    #[test]
    fn private_172_32_is_public() {
        // 172.32 is above the 172.16/12 range -> public.
        assert_eq!(classify_ip(ip("172.32.0.1")), None);
    }

    // --- link-local ---

    #[test]
    fn link_local_v6_blocked() {
        assert_eq!(classify_ip(ip("fe80::1")), Some(SsrfReason::LinkLocal));
    }

    // --- CGNAT (100.64.0.0/10) ---

    #[test]
    fn cgnat_low_blocked() {
        assert_eq!(classify_ip(ip("100.64.0.0")), Some(SsrfReason::CgNat));
    }

    #[test]
    fn cgnat_high_blocked() {
        assert_eq!(classify_ip(ip("100.127.255.255")), Some(SsrfReason::CgNat));
    }

    #[test]
    fn cgnat_just_below_is_public() {
        // 100.63.x is below 100.64.0.0/10 -> public.
        assert_eq!(classify_ip(ip("100.63.255.255")), None);
    }

    #[test]
    fn cgnat_just_above_is_public() {
        // 100.128.x is above 100.64.0.0/10 -> public.
        assert_eq!(classify_ip(ip("100.128.0.0")), None);
    }

    // --- unique-local (fc00::/7) ---

    #[test]
    fn unique_local_fc_blocked() {
        assert_eq!(classify_ip(ip("fc00::1")), Some(SsrfReason::UniqueLocal));
    }

    #[test]
    fn unique_local_fd_blocked() {
        assert_eq!(classify_ip(ip("fd12:3456::1")), Some(SsrfReason::UniqueLocal));
    }

    // --- multicast ---

    #[test]
    fn multicast_v4_blocked() {
        assert_eq!(classify_ip(ip("224.0.0.1")), Some(SsrfReason::Multicast));
        assert_eq!(classify_ip(ip("239.255.255.255")), Some(SsrfReason::Multicast));
    }

    #[test]
    fn multicast_v6_blocked() {
        assert_eq!(classify_ip(ip("ff02::1")), Some(SsrfReason::Multicast));
    }

    // --- unspecified ---

    #[test]
    fn unspecified_v4_blocked() {
        assert_eq!(classify_ip(ip("0.0.0.0")), Some(SsrfReason::Unspecified));
    }

    #[test]
    fn unspecified_v6_blocked() {
        assert_eq!(classify_ip(ip("::")), Some(SsrfReason::Unspecified));
    }

    // --- IPv4-mapped IPv6 must not bypass ---

    #[test]
    fn ipv4_mapped_loopback_blocked() {
        assert_eq!(classify_ip(ip("::ffff:127.0.0.1")), Some(SsrfReason::Loopback));
    }

    #[test]
    fn ipv4_mapped_metadata_blocked() {
        assert_eq!(
            classify_ip(ip("::ffff:169.254.169.254")),
            Some(SsrfReason::CloudMetadata)
        );
    }

    // --- public addresses allowed ---

    #[test]
    fn public_v4_allowed() {
        assert_eq!(classify_ip(ip("8.8.8.8")), None);
        assert_eq!(classify_ip(ip("1.1.1.1")), None);
        assert_eq!(classify_ip(ip("93.184.216.34")), None);
    }

    #[test]
    fn public_v6_allowed() {
        assert_eq!(classify_ip(ip("2606:4700:4700::1111")), None);
        assert_eq!(classify_ip(ip("2001:4860:4860::8888")), None);
    }

    // --- check_url ---

    fn parse(u: &str) -> url::Url {
        url::Url::parse(u).unwrap()
    }

    #[test]
    fn check_url_metadata_blocked() {
        assert_eq!(
            check_url(&parse("http://169.254.169.254/latest/meta-data/")),
            Err(SsrfReason::CloudMetadata)
        );
    }

    #[test]
    fn check_url_loopback_blocked() {
        assert_eq!(
            check_url(&parse("http://127.0.0.1:8080/admin")),
            Err(SsrfReason::Loopback)
        );
    }

    #[test]
    fn check_url_private_blocked() {
        assert_eq!(
            check_url(&parse("https://10.0.0.5/internal")),
            Err(SsrfReason::Private)
        );
    }

    #[test]
    fn check_url_ipv6_literal_blocked() {
        assert_eq!(
            check_url(&parse("http://[::1]:3000/")),
            Err(SsrfReason::Loopback)
        );
    }

    #[test]
    fn check_url_public_ip_allowed() {
        assert!(check_url(&parse("https://8.8.8.8/")).is_ok());
    }

    #[test]
    fn check_url_public_host_allowed() {
        assert!(check_url(&parse("https://api.example.com/v1/data")).is_ok());
        assert!(check_url(&parse("http://example.org/")).is_ok());
    }

    #[test]
    fn check_url_non_http_scheme_blocked() {
        assert_eq!(
            check_url(&parse("ftp://example.com/file")),
            Err(SsrfReason::NonHttpScheme)
        );
        assert_eq!(
            check_url(&parse("file:///etc/passwd")),
            Err(SsrfReason::NonHttpScheme)
        );
    }

    #[test]
    fn check_url_gopher_scheme_blocked() {
        assert_eq!(
            check_url(&parse("gopher://127.0.0.1:11211/_stats")),
            Err(SsrfReason::NonHttpScheme)
        );
    }

    #[test]
    fn check_url_metadata_hostname_passes_for_now() {
        // A hostname (not an IP literal) passes here — DNS-time resolution is a
        // documented follow-up. This test pins the current contract.
        assert!(check_url(&parse("http://metadata.google.internal/")).is_ok());
    }

    // --- SsrfReason Display / as_str ---

    #[test]
    fn reason_display_is_description() {
        assert_eq!(
            SsrfReason::CloudMetadata.to_string(),
            "cloud instance metadata endpoint"
        );
        assert_eq!(SsrfReason::Loopback.to_string(), "loopback address");
    }

    #[test]
    fn reason_as_str_is_stable() {
        assert_eq!(SsrfReason::Loopback.as_str(), "loopback");
        assert_eq!(SsrfReason::Private.as_str(), "private");
        assert_eq!(SsrfReason::LinkLocal.as_str(), "link-local");
        assert_eq!(SsrfReason::CgNat.as_str(), "cgnat");
        assert_eq!(SsrfReason::UniqueLocal.as_str(), "unique-local");
        assert_eq!(SsrfReason::Multicast.as_str(), "multicast");
        assert_eq!(SsrfReason::Unspecified.as_str(), "unspecified");
        assert_eq!(SsrfReason::CloudMetadata.as_str(), "cloud-metadata");
        assert_eq!(SsrfReason::NonHttpScheme.as_str(), "non-http-scheme");
        assert_eq!(SsrfReason::NoHost.as_str(), "no-host");
    }

    #[test]
    fn reason_is_copy_eq() {
        let a = SsrfReason::Private;
        let b = a;
        assert_eq!(a, b);
    }

    // --- check_url_resolved (DNS-time parity) ---

    #[tokio::test]
    async fn resolved_localhost_hostname_blocked() {
        // `localhost` resolves to 127.0.0.1 / ::1 (both loopback) with no
        // external network — the synchronous check_url passes it (it's a name),
        // but DNS-time resolution must block it.
        let r = check_url_resolved(&parse("http://localhost:8080/admin")).await;
        assert_eq!(r, Err(SsrfReason::Loopback));
    }

    #[tokio::test]
    async fn resolved_literal_metadata_still_blocked() {
        // IP literals are blocked by the synchronous path before any DNS.
        assert_eq!(
            check_url_resolved(&parse("http://169.254.169.254/latest/")).await,
            Err(SsrfReason::CloudMetadata)
        );
    }

    #[tokio::test]
    async fn resolved_non_http_scheme_blocked() {
        assert_eq!(
            check_url_resolved(&parse("ftp://localhost/x")).await,
            Err(SsrfReason::NonHttpScheme)
        );
    }

    #[tokio::test]
    async fn resolved_public_ip_literal_ok() {
        // Public IP literal: no DNS, classify says public.
        assert!(check_url_resolved(&parse("https://8.8.8.8/")).await.is_ok());
    }

    #[tokio::test]
    async fn resolved_unresolvable_host_passes() {
        // `.invalid` is RFC-6761-guaranteed never to resolve — a resolution
        // failure is not an SSRF risk, so it passes (the transport surfaces the
        // real connection error). Deterministic: no external network needed.
        let r = check_url_resolved(&parse("https://nonexistent.invalid/")).await;
        assert!(r.is_ok(), "unresolvable host should pass, got {r:?}");
    }
}
