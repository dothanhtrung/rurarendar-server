use argon2::{
    Algorithm,
    Argon2,
    Params,
    PasswordHasher,
    PasswordVerifier,
    Version,
};
use base64::Engine;
use base64::engine::general_purpose::{
    STANDARD,
    URL_SAFE_NO_PAD,
};
use rand::TryRng;
use time::{
    Date,
    Month,
    OffsetDateTime,
};

const TEMP_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const TOKEN_PREFIX: &str = "lad1_";

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let params = Params::new(19456, 2, 1, Some(32)).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    Argon2::default().verify_password(password.as_bytes(), hash).is_ok()
}

pub fn temporary_password() -> String {
    let mut rng = rand::rngs::SysRng;
    let mut out = String::with_capacity(16);
    for _ in 0..16 {
        let i = (rng.try_next_u32().expect("os rng") as usize) % TEMP_ALPHABET.len();
        out.push(TEMP_ALPHABET[i] as char);
    }
    out
}

pub fn issue_token() -> (String, Vec<u8>) {
    let mut raw = [0u8; 32];
    rand::rngs::SysRng.try_fill_bytes(&mut raw).expect("os rng");
    let token = format!("{TOKEN_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw));
    let hash = blake3::hash(&raw).as_bytes().to_vec();
    (token, hash)
}

pub fn token_hash_from_header(token: &str) -> Option<Vec<u8>> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let raw = URL_SAFE_NO_PAD.decode(rest.as_bytes()).ok()?;
    if raw.len() != 32 {
        return None;
    }
    Some(blake3::hash(&raw).as_bytes().to_vec())
}

pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, ()> {
    STANDARD.decode(s).map_err(|_| ())
}

pub fn encode_user_cursor(seq: i64) -> String {
    format!("u1.{}", URL_SAFE_NO_PAD.encode((seq as u64).to_be_bytes()))
}

pub fn decode_user_cursor(cursor: &str) -> Result<i64, ()> {
    if cursor.is_empty() {
        return Ok(0);
    }
    let rest = cursor.strip_prefix("u1.").ok_or(())?;
    let bytes = URL_SAFE_NO_PAD.decode(rest.as_bytes()).map_err(|_| ())?;
    if bytes.len() != 8 {
        return Err(());
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(u64::from_be_bytes(arr) as i64)
}

/// `YYYY-MM-DD` expires at the start of the next UTC day. An RFC3339 instant is used as given.
pub fn parse_expires_at(raw: &str) -> Result<OffsetDateTime, ()> {
    let s = raw.trim();
    if s.len() == 10 {
        let date = parse_utc_date(s)?;
        let next = date.next_day().ok_or(())?;
        return Ok(next.midnight().assume_utc());
    }
    if let Ok(t) = OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339) {
        return Ok(t);
    }
    let (head, frac) = s.split_once('.').ok_or(())?;
    let tz_at = frac.find(['Z', '+']).or_else(|| frac.rfind('-')).ok_or(())?;
    let normalized = format!("{head}{}", &frac[tz_at..]);
    OffsetDateTime::parse(&normalized, &time::format_description::well_known::Rfc3339).map_err(|_| ())
}

fn parse_utc_date(s: &str) -> Result<Date, ()> {
    let mut parts = s.split('-');
    let year: i32 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let month: u8 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let day: u8 = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    if parts.next().is_some() {
        return Err(());
    }
    Date::from_calendar_date(year, Month::try_from(month).map_err(|_| ())?, day).map_err(|_| ())
}

pub fn valid_username(name: &str) -> bool {
    let b = name.as_bytes();
    if b.len() < 3 || b.len() > 32 {
        return false;
    }
    if matches!(b[0], b'.' | b'-') || matches!(b[b.len() - 1], b'.' | b'-') {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PHC string from the argon2 test vectors for password "password".
    const LEGACY_HASH: &str =
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";

    #[test]
    fn verifies_existing_phc_hash() {
        assert!(verify_password("password", LEGACY_HASH));
        assert!(!verify_password("sassword", LEGACY_HASH));
        assert!(!verify_password("password", "not-a-hash"));
    }

    #[test]
    fn hashes_then_verifies() {
        let hash = hash_password("hunter2-password").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("hunter2-password", &hash));
        assert!(!verify_password("other-password", &hash));
    }

    #[test]
    fn temporary_password_uses_alphabet() {
        let password = temporary_password();
        assert_eq!(password.len(), 16);
        assert!(password.bytes().all(|b| TEMP_ALPHABET.contains(&b)));
    }

    #[test]
    fn parse_expires_at_accepts_a_date_or_an_instant() {
        let end = parse_expires_at("2026-10-02").unwrap();
        assert_eq!((end.year(), end.month(), end.day()), (2026, Month::October, 3));
        assert_eq!((end.hour(), end.minute(), end.second()), (0, 0, 0));

        let instant = parse_expires_at("2026-10-02T16:59:59Z").unwrap();
        assert_eq!(instant.hour(), 16);
        let with_fraction = parse_expires_at("2026-10-02T16:59:59.000Z").unwrap();
        assert_eq!(with_fraction, instant);

        assert!(parse_expires_at("nope").is_err());
        assert!(parse_expires_at("2026-13-40").is_err());
    }

    #[test]
    fn issued_token_roundtrips_to_its_hash() {
        let (token, hash) = issue_token();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token_hash_from_header(&token), Some(hash));
        assert!(token_hash_from_header("nope").is_none());
    }
}
