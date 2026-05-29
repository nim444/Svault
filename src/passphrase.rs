pub struct StrengthWarning(pub String);

/// Minimum estimated entropy (bits) a passphrase must clear at create/recover
/// time unless `--force` is given. ~50 bits is well past trivially brute-forced
/// while still reachable with a short passphrase that mixes character classes
/// (e.g. a 10-char mixed passphrase ≈ 60 bits) or a 4-word passphrase.
pub const MIN_ENTROPY_BITS: f64 = 50.0;

/// Conservative entropy estimate: `length × log2(pool)`, where `pool` is the
/// sum of the character classes present. It deliberately does **not** model
/// dictionary words or patterns (so it never over-credits), which is why
/// [`check`] still runs its common-word/variety heuristics on top. Enough for a
/// floor, not a strength meter.
pub fn entropy_bits(passphrase: &str) -> f64 {
    let mut pool = 0u32;
    if passphrase.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if passphrase.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if passphrase
        .chars()
        .any(|c| c.is_ascii_punctuation() || c == ' ')
    {
        pool += 33;
    }
    if !passphrase.is_ascii() {
        pool += 100; // any non-ASCII char widens the pool substantially
    }
    if pool == 0 {
        return 0.0;
    }
    passphrase.chars().count() as f64 * (pool as f64).log2()
}

/// Hard floor enforced at create/recover (unless `--force`): `Err` with a
/// user-facing message when the estimate is below [`MIN_ENTROPY_BITS`].
pub fn meets_floor(passphrase: &str) -> Result<(), String> {
    let bits = entropy_bits(passphrase);
    if bits < MIN_ENTROPY_BITS {
        return Err(format!(
            "passphrase is too weak (~{bits:.0} bits, need {MIN_ENTROPY_BITS:.0}) — \
             use a longer or more varied passphrase, or pass --force to override"
        ));
    }
    Ok(())
}

pub fn check(passphrase: &str) -> Option<StrengthWarning> {
    if passphrase.len() < 12 {
        return Some(StrengthWarning(
            "Passphrase is short (< 12 chars). A weak passphrase is the easiest attack vector."
                .into(),
        ));
    }
    let has_upper = passphrase.chars().any(|c| c.is_uppercase());
    let has_lower = passphrase.chars().any(|c| c.is_lowercase());
    let has_digit = passphrase.chars().any(|c| c.is_ascii_digit());
    let has_symbol = passphrase.chars().any(|c| !c.is_alphanumeric());
    let variety = [has_upper, has_lower, has_digit, has_symbol]
        .iter()
        .filter(|&&v| v)
        .count();

    if variety < 2 {
        return Some(StrengthWarning(
            "Passphrase uses only one character type. Mix letters, numbers, and symbols.".into(),
        ));
    }
    let common = [
        "password",
        "passphrase",
        "secret",
        "admin",
        "svault",
        "123456",
        "qwerty",
    ];
    let lower = passphrase.to_lowercase();
    if common.iter().any(|w| lower.contains(w)) {
        return Some(StrengthWarning(
            "Passphrase contains a common word. Choose something less predictable.".into(),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_passphrase_passes() {
        assert!(check("Str0ng!Phrase#99").is_none());
    }

    #[test]
    fn short_passphrase_warns() {
        assert!(check("ab1!").is_some());
    }

    #[test]
    fn single_character_type_warns() {
        // 16 chars but lowercase only — fails the variety check.
        assert!(check("abcdefghijklmnop").is_some());
    }

    #[test]
    fn common_word_warns() {
        // Long and varied, but contains "password".
        assert!(check("MyPassword123!").is_some());
    }

    #[test]
    fn entropy_floor_rejects_weak_and_accepts_strong() {
        // Short, single-class → well under the floor.
        assert!(meets_floor("abcdef").is_err());
        // Short even with mixed classes → still under (length matters).
        assert!(meets_floor("Ab1!").is_err());
        // A 10-char mixed passphrase clears ~50 bits.
        assert!(meets_floor("Str0ng!Pass#99").is_ok());
        // A long all-lowercase passphrase clears the floor on length alone.
        assert!(meets_floor("correcthorsebatterystaple").is_ok());
        // Empty → zero entropy.
        assert_eq!(entropy_bits(""), 0.0);
    }
}
