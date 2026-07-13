pub fn validate_email(email: &str) -> bool {
    // Simple robust regex/check for RFC email format
    // A simple validation: must contain @ and a domain with dot, no spaces
    if email.is_empty() || email.contains(' ') {
        return false;
    }
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let domain = parts[1];
    domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
}

pub fn validate_password(password: &str) -> bool {
    let len = password.len();
    if len < 12 || len > 256 {
        return false;
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii_punctuation() || !c.is_alphanumeric() {
            // covers standard ascii punctuation and non-alphanumeric chars
            has_special = true;
        }
    }

    has_upper && has_lower && has_digit && has_special
}
