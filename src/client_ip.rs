//! Safe client address derivation and privacy-preserving rate-limit bucketing for
//! `POST /v1/register`.
//!
//! Forwarded headers (`X-Forwarded-For` by default) are honoured ONLY when the TCP peer
//! address belongs to a configured trusted proxy CIDR. Client addresses are never logged
//! and are hashed before being stored in rate-limit buckets.

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use axum::http::{HeaderMap, HeaderName};
use ipnet::IpNet;
use ring::digest;

use crate::crypto::b64_encode;

/// Default forwarded header inspected when a request arrives from a trusted proxy.
pub const DEFAULT_TRUSTED_PROXY_HEADER: &str = "x-forwarded-for";

const IP_BUCKET_DOMAIN: &[u8] = b"pubky-dispatch-push-relay/v1/ip-bucket:";

/// Configured set of trusted reverse-proxy CIDR blocks.
///
/// Empty by default: no forwarded header is trusted unless explicitly configured.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies {
    cidrs: Vec<IpNet>,
}

impl TrustedProxies {
    /// Creates an empty trusted-proxy set that trusts no forwarded headers.
    #[must_use]
    pub const fn none() -> Self {
        Self { cidrs: Vec::new() }
    }

    /// Creates a trusted-proxy set from pre-parsed [`IpNet`] ranges.
    #[must_use]
    pub const fn from_cidrs(cidrs: Vec<IpNet>) -> Self {
        Self { cidrs }
    }

    /// Parses a comma-separated list of IP addresses or CIDR ranges (e.g.
    /// `"127.0.0.1/32,10.0.0.0/8,::1"`). Bare IP addresses are normalized to `/32` or `/128`.
    ///
    /// # Errors
    ///
    /// Returns an error string if any entry is neither a valid CIDR nor a valid IP address.
    pub fn parse_csv(csv: &str) -> Result<Self, String> {
        let mut cidrs = Vec::new();
        for raw in csv.split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            if let Ok(net) = IpNet::from_str(item) {
                cidrs.push(net.trunc());
            } else if let Ok(ip) = IpAddr::from_str(item) {
                cidrs.push(IpNet::from(ip));
            } else {
                return Err(format!("invalid trusted proxy CIDR or IP: {item}"));
            }
        }
        Ok(Self { cidrs })
    }

    /// Returns `true` if `ip` belongs to any configured trusted proxy range.
    #[must_use]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let canonical = canonicalize_ip(ip);
        self.cidrs.iter().any(|net| net.contains(&canonical))
    }

    /// Derives the effective client IP for rate limiting.
    ///
    /// If `peer_ip` is NOT in [`TrustedProxies`], forwarded headers are ignored completely
    /// and `peer_ip` is returned. If `peer_ip` IS trusted, `header_name` entries are parsed
    /// strictly right-to-left skipping trusted proxies and returning the rightmost valid
    /// untrusted address. Any malformed attacker-supplied entries to its left are ignored;
    /// a malformed entry encountered before finding an untrusted IP falls back to `peer_ip`.
    #[must_use]
    pub fn extract_client_ip(
        &self,
        peer_ip: IpAddr,
        headers: &HeaderMap,
        header_name: &str,
    ) -> IpAddr {
        let peer_ip = canonicalize_ip(peer_ip);
        if !self.is_trusted(peer_ip) {
            return peer_ip;
        }
        let Ok(name) = HeaderName::from_bytes(header_name.as_bytes()) else {
            return peer_ip;
        };

        let header_values: Vec<_> = headers.get_all(&name).iter().collect();
        for value in header_values.into_iter().rev() {
            for segment in value.as_bytes().rsplit(|&b| b == b',') {
                let trimmed = trim_ascii_whitespace(segment);
                if trimmed.is_empty() {
                    continue;
                }
                let Ok(text) = std::str::from_utf8(trimmed) else {
                    return peer_ip;
                };
                let Ok(ip) = IpAddr::from_str(text) else {
                    return peer_ip;
                };
                let canonical = canonicalize_ip(ip);
                if !self.is_trusted(canonical) {
                    return canonical;
                }
            }
        }

        peer_ip
    }
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((&last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

/// Converts a client IP into a privacy-preserving, deterministic rate-limit bucket key.
///
/// IPv4 addresses (including IPv4-mapped IPv6 `::ffff:a.b.c.d`) are bucketed per `/32`;
/// IPv6 addresses are bucketed per `/64` prefix so a single allocation cannot bypass limits
/// by rotating interface identifiers. The canonical prefix is SHA-256 hashed so raw client
/// IP addresses are not stored in rate-limit tables.
#[must_use]
pub fn ip_rate_limit_key(ip: IpAddr) -> String {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(IP_BUCKET_DOMAIN);
    match canonicalize_ip(ip) {
        IpAddr::V4(v4) => {
            ctx.update(&[4]);
            ctx.update(&v4.octets());
        }
        IpAddr::V6(v6) => {
            ctx.update(&[6]);
            let octets = v6.octets();
            ctx.update(&octets[..8]);
        }
    }
    let hash = ctx.finish();
    b64_encode(hash.as_ref())
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                IpAddr::V4(mapped)
            } else {
                IpAddr::V6(Ipv6Addr::from(v6.octets()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ignores_forwarded_header_when_peer_is_untrusted() {
        let proxies = TrustedProxies::parse_csv("10.0.0.0/8").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.9"));

        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        assert_eq!(
            proxies.extract_client_ip(peer, &headers, DEFAULT_TRUSTED_PROXY_HEADER),
            peer
        );
    }

    #[test]
    fn walks_forwarded_for_right_to_left_for_trusted_proxies() {
        let proxies = TrustedProxies::parse_csv("10.0.0.0/8,127.0.0.1").unwrap();
        let mut headers = HeaderMap::new();
        // Attacker spoofed 1.2.3.4 on the left; real client is 203.0.113.7; internal hop 10.1.2.3.
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 203.0.113.7, 10.1.2.3"),
        );

        let peer = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            proxies.extract_client_ip(peer, &headers, DEFAULT_TRUSTED_PROXY_HEADER),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn right_to_left_ignores_malformed_left_entries_but_rejects_malformed_right_hops() {
        let proxies = TrustedProxies::parse_csv("10.0.0.0/8").unwrap();
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Attacker sent malformed garbage on the left; trusted proxies appended real client & hop.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("garbage, 203.0.113.5, 10.0.0.1"),
        );
        assert_eq!(
            proxies.extract_client_ip(peer, &headers, DEFAULT_TRUSTED_PROXY_HEADER),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
        );

        // Multiple XFF headers: garbage in an earlier header does not poison rightmost valid hop.
        let mut multi = HeaderMap::new();
        multi.append("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        multi.append(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.9, 10.0.0.1"),
        );
        assert_eq!(
            proxies.extract_client_ip(peer, &multi, DEFAULT_TRUSTED_PROXY_HEADER),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
        );

        // Malformed entry to the right of an attacker IP stops traversal and falls back to peer.
        let mut poisoned = HeaderMap::new();
        poisoned.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, garbage, 10.0.0.1"),
        );
        assert_eq!(
            proxies.extract_client_ip(peer, &poisoned, DEFAULT_TRUSTED_PROXY_HEADER),
            peer
        );

        // Non-ASCII prefix on the left MUST NOT discard a valid rightmost IP appended by a proxy.
        let mut non_ascii_left = HeaderMap::new();
        non_ascii_left.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"\xffbad, 203.0.113.5, 10.0.0.1").unwrap(),
        );
        assert_eq!(
            proxies.extract_client_ip(peer, &non_ascii_left, DEFAULT_TRUSTED_PROXY_HEADER),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
        );

        // Non-ASCII hop to the right of an attacker IP still stops traversal safely at peer.
        let mut non_ascii_right = HeaderMap::new();
        non_ascii_right.insert(
            "x-forwarded-for",
            HeaderValue::from_bytes(b"1.2.3.4, \xffbad, 10.0.0.1").unwrap(),
        );
        assert_eq!(
            proxies.extract_client_ip(peer, &non_ascii_right, DEFAULT_TRUSTED_PROXY_HEADER),
            peer
        );
    }

    #[test]
    fn buckets_ipv6_by_slash_64_and_hashes_addresses() {
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1111, 0x2222, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1111, 0x2222, 9, 9, 9, 9));
        let c = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x1111, 0x2223, 0, 0, 0, 1));

        assert_eq!(ip_rate_limit_key(a), ip_rate_limit_key(b));
        assert_ne!(ip_rate_limit_key(a), ip_rate_limit_key(c));

        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 42).to_ipv6_mapped());
        assert_eq!(ip_rate_limit_key(v4), ip_rate_limit_key(mapped));
        assert!(!ip_rate_limit_key(v4).contains("203.0.113.42"));
    }
}
