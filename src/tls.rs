//! Typed TLS-fingerprint profiles for the HTTP client.
//!
//! The default [`TlsProfile::Rustls`] uses reqwest's rustls stack — an honest
//! "I am rustls" ClientHello. The browser-emulating profiles reproduce a real
//! browser's JA3/JA4 ClientHello (cipher ordering, extension list, GREASE,
//! ALPN, HTTP/2 SETTINGS) so a TLS-fingerprinting WAF cannot distinguish the
//! client from that browser. They require the `stealth` cargo feature (which
//! pulls `wreq` / BoringSSL); requesting one without the feature is a typed
//! build error ([`crate::TodokuError::UnsupportedTlsProfile`]) — todoku never
//! silently falls back to the rustls fingerprint when an emulated one was
//! asked for.
//!
//! This is the pleme-io absorption of Obscura's stealth networking: Obscura
//! gates the same capability behind its own `--features stealth` wreq swap.

/// The TLS fingerprint the client presents on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TlsProfile {
    /// reqwest + rustls. Honest fingerprint, available in every build.
    #[default]
    Rustls,
    /// Emulate Chrome's ClientHello (JA3/JA4). Requires `stealth`.
    Chrome,
    /// Emulate Firefox's ClientHello (JA3/JA4). Requires `stealth`.
    Firefox,
    /// Emulate Safari's ClientHello (JA3/JA4). Requires `stealth`.
    Safari,
}

impl TlsProfile {
    /// Stable lowercase identifier (used in errors + logs).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rustls => "rustls",
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
            Self::Safari => "safari",
        }
    }

    /// Whether this profile emulates a real browser (vs the honest rustls
    /// fingerprint).
    #[must_use]
    pub fn is_emulated(self) -> bool {
        !matches!(self, Self::Rustls)
    }

    /// Whether honoring this profile requires the `stealth` feature.
    #[must_use]
    pub fn requires_stealth(self) -> bool {
        self.is_emulated()
    }

    /// Whether *this build* can honor this profile (true for `Rustls` always;
    /// for emulated profiles only when compiled with the `stealth` feature).
    #[must_use]
    pub fn available(self) -> bool {
        if self.is_emulated() {
            cfg!(feature = "stealth")
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_rustls() {
        assert_eq!(TlsProfile::default(), TlsProfile::Rustls);
    }

    #[test]
    fn as_str_is_stable() {
        assert_eq!(TlsProfile::Rustls.as_str(), "rustls");
        assert_eq!(TlsProfile::Chrome.as_str(), "chrome");
        assert_eq!(TlsProfile::Firefox.as_str(), "firefox");
        assert_eq!(TlsProfile::Safari.as_str(), "safari");
    }

    #[test]
    fn rustls_is_not_emulated() {
        assert!(!TlsProfile::Rustls.is_emulated());
        assert!(!TlsProfile::Rustls.requires_stealth());
    }

    #[test]
    fn browser_profiles_are_emulated() {
        for p in [TlsProfile::Chrome, TlsProfile::Firefox, TlsProfile::Safari] {
            assert!(p.is_emulated());
            assert!(p.requires_stealth());
        }
    }

    #[test]
    fn rustls_always_available() {
        assert!(TlsProfile::Rustls.available());
    }

    #[test]
    fn emulated_availability_tracks_feature() {
        // Without `stealth`, emulated profiles are unavailable; with it, available.
        let expected = cfg!(feature = "stealth");
        assert_eq!(TlsProfile::Chrome.available(), expected);
        assert_eq!(TlsProfile::Firefox.available(), expected);
        assert_eq!(TlsProfile::Safari.available(), expected);
    }

    #[test]
    fn profile_is_copy_eq() {
        let a = TlsProfile::Chrome;
        let b = a;
        assert_eq!(a, b);
    }
}
