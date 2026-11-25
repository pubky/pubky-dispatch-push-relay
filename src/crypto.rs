//! Wire Format encodings (`lp()`, strict base64url) and strict Ed25519 verification.
//!
//! Implements Wire Format §1.2 (base64url without padding), §1.4 (`lp()` length-prefixing),
//! §2.1 (strict four-step Ed25519 verification), and §8.2 (push webhook signature input and
//! exact host-preserving relay origin derivation).

use base64::Engine as _;
use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use thiserror::Error;
use url::Url;

/// Canonical webhook signature HTTP header for Pubky Dispatch.
pub const SIGNATURE_HEADER: &str = "Dispatch-Signature";

/// Canonical Ed25519 signing label for Pubky Dispatch push webhooks.
pub const SIGNING_LABEL: &str = "pubky-dispatch/v1/push";

/// Cryptographic and encoding errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Value is not canonical unpadded base64url.
    #[error("invalid base64url encoding")]
    InvalidBase64,
    /// Decoded byte length did not match the expected fixed size.
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected byte length.
        expected: usize,
        /// Actual decoded byte length.
        actual: usize,
    },
    /// Public key is invalid, non-canonical, or of small order.
    #[error("invalid Ed25519 public key: {0}")]
    InvalidPublicKey(&'static str),
    /// Ed25519 signature failed strict Wire Format §2.1 verification.
    #[error("invalid Ed25519 signature: {0}")]
    InvalidSignature(&'static str),
    /// Relay origin or URL does not satisfy Wire Format §8.2.
    #[error("invalid relay origin: {0}")]
    InvalidOrigin(&'static str),
    /// Operating system CSPRNG failed.
    #[error("failed to generate random bytes")]
    RngFailure,
}

/// Encodes `bytes` as base64url without padding (Wire Format §1.2).
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes strict unpadded base64url (Wire Format §1.2).
///
/// Rejects `=` padding, `+` and `/`, whitespace, invalid lengths, and non-zero trailing
/// bits so every byte string has a single canonical encoding.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidBase64`] if decoding fails.
pub fn b64_decode(text: &str) -> Result<Vec<u8>, CryptoError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| CryptoError::InvalidBase64)
}

/// Decodes strict unpadded base64url of exact byte length `N` (Wire Format §1.2).
///
/// # Errors
///
/// Returns [`CryptoError::InvalidBase64`] or [`CryptoError::InvalidLength`].
pub fn b64_decode_array<const N: usize>(text: &str) -> Result<[u8; N], CryptoError> {
    let bytes = b64_decode(text)?;
    let actual = bytes.len();
    bytes.try_into().map_err(|_| CryptoError::InvalidLength {
        expected: N,
        actual,
    })
}

/// Length-prefixed concatenation `lp(x1, ..., xn) = u32_be(len(x1)) || x1 || ...`
/// (Wire Format §1.4).
#[must_use]
pub fn lp(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len().saturating_add(4)).sum();
    let mut out = Vec::with_capacity(total);
    for part in parts {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(part.get(..len as usize).unwrap_or(part));
    }
    out
}

/// Constructs the Wire Format §2.1 signature input `lp(label, field1, ..., fieldn)`.
#[must_use]
pub fn signed_bytes(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut parts = Vec::with_capacity(fields.len() + 1);
    parts.push(label.as_bytes());
    parts.extend_from_slice(fields);
    lp(&parts)
}

/// Validates that `public` is a canonical, non-small-order Ed25519 public key
/// (Wire Format §2.1 steps 2 and 3 for `A`).
///
/// Mixed-order keys (order `8L`) are permitted per RFC 8032 and Wire Format §2.1.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] if `A` is non-canonical or small-order.
pub fn validate_public_key(public: &[u8; 32]) -> Result<(), CryptoError> {
    let Some(point) = CompressedEdwardsY(*public)
        .decompress()
        .filter(|decoded| decoded.compress().to_bytes() == *public)
    else {
        return Err(CryptoError::InvalidPublicKey(
            "public key is invalid or non-canonical",
        ));
    };

    if point.is_small_order() {
        return Err(CryptoError::InvalidPublicKey("public key is small-order"));
    }

    Ok(())
}

/// Verifies an Ed25519 signature over raw `message` bytes following all four steps of
/// Wire Format §2.1 in order:
///
/// 1. `S < L` (canonical scalar).
/// 2. `A` (public key) and `R` (first 32 signature bytes) decompress and re-encode to
///    the exact input bytes.
/// 3. Neither `A` nor `R` is of small order (`[8]A != I` and `[8]R != I`).
/// 4. Cofactorless equation `[S]B - [k]A == R` holds byte-for-byte.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] naming the check that failed.
pub fn verify_ed25519(
    public: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let (r_slice, s_slice) = signature.split_at(32);

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(s_slice);
    if Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_none() {
        return Err(CryptoError::InvalidSignature(
            "S is not below group order L",
        ));
    }

    let canonical = |bytes: &[u8]| {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        CompressedEdwardsY(arr)
            .decompress()
            .filter(|decoded| decoded.compress().to_bytes() == arr)
    };

    let Some(a_point) = canonical(public) else {
        return Err(CryptoError::InvalidSignature(
            "public key A is invalid or non-canonical",
        ));
    };
    let Some(r_point) = canonical(r_slice) else {
        return Err(CryptoError::InvalidSignature(
            "R is invalid or non-canonical",
        ));
    };

    if a_point.is_small_order() {
        return Err(CryptoError::InvalidSignature("public key A is small-order"));
    }
    if r_point.is_small_order() {
        return Err(CryptoError::InvalidSignature("R is small-order"));
    }

    let verifying_key = VerifyingKey::from_bytes(public)
        .map_err(|_| CryptoError::InvalidSignature("invalid public key"))?;

    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature("cofactorless equation does not hold"))
}

/// Verifies a push webhook signature over `lp(label, relay_origin, raw_body)`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidSignature`] if verification fails.
pub fn verify_webhook_signature(
    push_key: &[u8; 32],
    label: &str,
    relay_origin: &str,
    raw_body: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let message = signed_bytes(label, &[relay_origin.as_bytes(), raw_body]);
    verify_ed25519(push_key, &message, signature)
}

/// Signs a push webhook over `lp(label, relay_origin, raw_body)`.
#[must_use]
pub fn sign_webhook(
    signing_key: &SigningKey,
    label: &str,
    relay_origin: &str,
    raw_body: &[u8],
) -> [u8; 64] {
    let message = signed_bytes(label, &[relay_origin.as_bytes(), raw_body]);
    signing_key.sign(&message).to_bytes()
}

/// Generates a cryptographically random opaque push handle (`b64(16)`, 22 characters)
/// per Wire Format §1.7.
///
/// # Errors
///
/// Returns [`CryptoError::RngFailure`] if the OS CSPRNG fails.
pub fn generate_handle() -> Result<String, CryptoError> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| CryptoError::RngFailure)?;
    Ok(b64_encode(&raw))
}

/// Derives the relay origin signed by the Dispatch service from a `relay_url`:
/// `https://` followed by the URL's host **as written** (preserving host case), without
/// port or path (Wire Format §8.2).
///
/// Matches the reference `relay_origin` derivation byte-for-byte.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidOrigin`] if the URL is not `https://` or has no host.
pub fn relay_origin(relay_url: &str) -> Result<String, CryptoError> {
    let Some(rest) = relay_url.strip_prefix("https://") else {
        return Err(CryptoError::InvalidOrigin("scheme must be lowercase https"));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split_once(']').map_or("", |(inner, _)| inner)
    } else {
        host.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return Err(CryptoError::InvalidOrigin("missing host"));
    }
    if relay_url.contains("://[") {
        return Ok(format!("https://[{host}]"));
    }
    Ok(format!("https://{host}"))
}

/// Validates a configured `RELAY_ORIGIN` value (`https://<host>` with no port, path,
/// trailing slash, query, fragment, or userinfo) while preserving exact host spelling
/// so signatures produced by [`relay_origin`] verify identically.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidOrigin`] if `input` is not a bare `https://<host>` origin.
pub fn validate_relay_origin(input: &str) -> Result<String, CryptoError> {
    if !input.starts_with("https://") {
        return Err(CryptoError::InvalidOrigin("scheme must be lowercase https"));
    }
    let parsed = Url::parse(input).map_err(|_| CryptoError::InvalidOrigin("not a valid URL"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CryptoError::InvalidOrigin("must not contain userinfo"));
    }
    if parsed.port().is_some() {
        return Err(CryptoError::InvalidOrigin(
            "must not include an explicit port",
        ));
    }
    if parsed.path() != "/" && !parsed.path().is_empty() {
        return Err(CryptoError::InvalidOrigin("must not include a path"));
    }
    if input.ends_with('/') {
        return Err(CryptoError::InvalidOrigin("must not have a trailing slash"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(CryptoError::InvalidOrigin(
            "must not include query or fragment",
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(CryptoError::InvalidOrigin("missing host"));
    }
    let derived = relay_origin(input)?;
    if derived != input {
        return Err(CryptoError::InvalidOrigin(
            "must be bare https://<host> without explicit port or trailing slash",
        ));
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lp_encodes_big_endian_length_prefixes() {
        assert_eq!(lp(&[]), Vec::<u8>::new());
        assert_eq!(
            lp(&[b"abc", b"", b"d"]),
            vec![0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 0, 0, 0, 0, 0, 1, b'd']
        );
    }

    #[test]
    fn base64url_rejects_padding_and_non_canonical_bits() {
        assert_eq!(b64_encode(&[1, 2, 3]), "AQID");
        assert_eq!(b64_decode("AQID").unwrap(), vec![1, 2, 3]);
        assert!(b64_decode("AQI=").is_err());
        assert!(b64_decode("AQ+D").is_err());
        assert!(b64_decode("AQ/D").is_err());
        assert!(b64_decode("AQ ID").is_err());
        assert!(b64_decode("AB").is_err());
    }

    #[test]
    fn verifies_official_dispatch_webhook_vector_byte_for_byte() {
        const RELAY_URL: &str = "https://push.example/v1/hook";
        const BODY: &[u8] = br#"{"v":1,"handle":"dH9r2POzhkcCmW_2TUIRFQ","ts":"2026-01-01T00:06:00.000Z","nonce":"dgOrMASIWFmulwUPwzWlpQ"}"#;
        const SIG_B64: &str = "1v9TMYsaXAjcvHnXWQYYOkVazExu5r1f6Vvj_mx0GKpjz0tV5eq_VGPzzgrBhqxdaOVC5P-4ZGAq2Y0D4fHuAg";
        const KEY_B64: &str = "A_K47RLrjHBBJq2U9QpYGAjLCAIXJMic1XscmVFqPBc";
        const SECRET_HEX: &str = "f4405752785ae5e245e1c62394e86c8349e0e7612e67b7cb100f93de800a02fe";
        const SIGNED_BYTES_HEX: &str = "000000167075626b792d64697370617463682f76312f707573680000001468747470733a2f2f707573682e6578616d706c650000006a7b2276223a312c2268616e646c65223a226448397232504f7a686b63436d575f32545549524651222c227473223a22323032362d30312d30315430303a30363a30302e3030305a222c226e6f6e6365223a2264674f724d41534957466d756c775550777a576c7051227d";

        let origin = relay_origin(RELAY_URL).unwrap();
        assert_eq!(origin, "https://push.example");

        let signed_bytes = lp(&[SIGNING_LABEL.as_bytes(), origin.as_bytes(), BODY]);
        assert_eq!(hex::encode(&signed_bytes), SIGNED_BYTES_HEX);

        let public_key = b64_decode_array::<32>(KEY_B64).unwrap();
        let signature = b64_decode_array::<64>(SIG_B64).unwrap();
        let secret: [u8; 32] = hex::decode(SECRET_HEX).unwrap().try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&secret);

        assert_eq!(signing_key.verifying_key().to_bytes(), public_key);

        let recomputed = sign_webhook(&signing_key, SIGNING_LABEL, &origin, BODY);
        assert_eq!(b64_encode(&recomputed), SIG_B64);

        verify_webhook_signature(&public_key, SIGNING_LABEL, &origin, BODY, &signature).unwrap();

        assert!(
            verify_webhook_signature(
                &public_key,
                "pubky-dispatch/v2/push",
                &origin,
                BODY,
                &signature
            )
            .is_err()
        );
        assert!(
            verify_webhook_signature(
                &public_key,
                SIGNING_LABEL,
                "https://elsewhere.example",
                BODY,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn enforces_wire_format_2_1_ed25519_edge_vectors() {
        let mixed_pk =
            b64_decode_array::<32>("24Lckov6KOJN4tsUEWMhSwTZt3TpVeUuffhN6CG4Qik").unwrap();
        let mixed_sig = b64_decode_array::<64>(
            "c3swFHdq_tarBQA6c9ZbNOMtGthN3BRmmi200Se7unMC_jlEZqZjJ2twbhHq7VV184SVpgej_bYZBj7bLridAA",
        )
        .unwrap();
        let mixed_msg = hex::decode(
            "0000001a7075626b792d7377697463682f76312f6170702d7265636f72640000002d7075626b792d73776974636820463532206564676520636173653a206d697865642d6f72646572206b65792032",
        )
        .unwrap();
        assert!(validate_public_key(&mixed_pk).is_ok());
        assert!(verify_ed25519(&mixed_pk, &mixed_msg, &mixed_sig).is_ok());

        let cases: &[(&str, &str, &str, &str)] = &[
            (
                "small-order identity public key",
                "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "000000187075626b792d7377697463682f76312f6170702d63657274000000027b7d",
            ),
            (
                "cofactored equation only",
                "24Lckov6KOJN4tsUEWMhSwTZt3TpVeUuffhN6CG4Qik",
                "c3swFHdq_tarBQA6c9ZbNOMtGthN3BRmmi200Se7unO1jK0-Xy9xsvZT1LEyfS8iYaJ7Aenwujy858CnQbE-Dw",
                "0000001a7075626b792d7377697463682f76312f6170702d7265636f72640000002d7075626b792d73776974636820463532206564676520636173653a20636f666163746f726564206f6e6c792032",
            ),
            (
                "small-order R",
                "24Lckov6KOJN4tsUEWMhSwTZt3TpVeUuffhN6CG4Qik",
                "7P_______________________________________3-Hho9H9JHdlMbVcwY0UFMsCKFbi42Jf_QJIkT9WXViDQ",
                "0000001a7075626b792d7377697463682f76312f6170702d7265636f72640000002b7075626b792d73776974636820463532206564676520636173653a20736d616c6c2d6f7264657220522031",
            ),
            (
                "non-canonical R",
                "24Lckov6KOJN4tsUEWMhSwTZt3TpVeUuffhN6CG4Qik",
                "7v_______________________________________3_3_wVRkvcm5z_PfX9W3-RyFupMwGwpXr602nS7ANWtDg",
                "0000001a7075626b792d7377697463682f76312f6170702d7265636f72640000002d7075626b792d73776974636820463532206564676520636173653a206e6f6e2d63616e6f6e6963616c20522030",
            ),
            (
                "non-canonical public key y+p",
                "8P_______________________________________38",
                "c3swFHdq_tarBQA6c9ZbNOMtGthN3BRmmi200Se7unP1-h9-pB_rsoGm0URWvw1UtPJlqH-4RtzD5-1rw0fbCg",
                "0000001a7075626b792d7377697463682f76312f6170702d7265636f7264000000347075626b792d73776974636820463532206564676520636173653a206e6f6e2d63616e6f6e6963616c207075626c6963206b6579",
            ),
            (
                "small-order public key of order 8",
                "xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o",
                "c3swFHdq_tarBQA6c9ZbNOMtGthN3BRmmi200Se7unP1-h9-pB_rsoGm0URWvw1UtPJlqH-4RtzD5-1rw0fbCg",
                "0000001a7075626b792d7377697463682f76312f6170702d7265636f7264000000327075626b792d73776974636820463532206564676520636173653a20736d616c6c2d6f72646572207075626c6963206b6579",
            ),
        ];

        for (name, pk_b64, sig_b64, msg_hex) in cases {
            let pk = b64_decode_array::<32>(pk_b64).unwrap();
            let sig = b64_decode_array::<64>(sig_b64).unwrap();
            let msg = hex::decode(msg_hex).unwrap();
            assert!(
                verify_ed25519(&pk, &msg, &sig).is_err(),
                "expected rejection for {name}"
            );
        }

        let non_canon_pk =
            b64_decode_array::<32>("8P_______________________________________38").unwrap();
        assert!(validate_public_key(&non_canon_pk).is_err());

        let order8_pk =
            b64_decode_array::<32>("xxdqcD1N2E-6PAt2DRBnDyogU_osOczGTsf9d5KsA3o").unwrap();
        assert!(validate_public_key(&order8_pk).is_err());
    }

    #[test]
    fn relay_origin_preserves_mixed_case_host_spelling() {
        assert_eq!(
            relay_origin("https://Push.Example/v1/hook").unwrap(),
            "https://Push.Example"
        );
        assert_eq!(
            validate_relay_origin("https://Push.Example").unwrap(),
            "https://Push.Example"
        );
        assert_eq!(
            validate_relay_origin("https://[2001:db8::1]").unwrap(),
            "https://[2001:db8::1]"
        );

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let body = br#"{"v":1,"handle":"abc","ts":"2026-01-01T00:06:00.000Z","nonce":"vX9AwGixjY0MiVA86rs3Gw"}"#;
        let service_origin = relay_origin("https://Push.Example/v1/hook").unwrap();
        let configured_origin = validate_relay_origin("https://Push.Example").unwrap();
        let sig = sign_webhook(&key, SIGNING_LABEL, &service_origin, body);
        assert!(
            verify_webhook_signature(
                &key.verifying_key().to_bytes(),
                SIGNING_LABEL,
                &configured_origin,
                body,
                &sig
            )
            .is_ok()
        );

        for bad in [
            "http://push.example",
            "HTTPS://push.example",
            "https://push.example/",
            "https://push.example/v1/hook",
            "https://push.example:443",
            "https://push.example:8443",
            "https://user@push.example",
            "https://push.example?a=1",
            "https://push.example#frag",
            "not-a-url",
        ] {
            assert!(
                validate_relay_origin(bad).is_err(),
                "expected error for {bad}"
            );
        }
    }

    #[test]
    fn generates_unique_22_char_handles() {
        let a = generate_handle().unwrap();
        let b = generate_handle().unwrap();
        assert_eq!(a.len(), 22);
        assert_eq!(b.len(), 22);
        assert_ne!(a, b);
        assert!(b64_decode_array::<16>(&a).is_ok());
    }
}
