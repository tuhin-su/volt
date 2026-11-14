use chrono::Utc;

/// Returns current UTC timestamp in ISO 8601 / RFC 3339 format with millisecond precision
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

/// Returns timestamp formatted for safe filename use (e.g. "20261114_231500_123")
pub fn now_filename_safe() -> String {
    Utc::now().format("%Y%m%d_%H%M%S_%3f").to_string()
}
