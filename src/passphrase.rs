pub struct StrengthWarning(pub String);

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
}
