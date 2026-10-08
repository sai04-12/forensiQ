use chrono::{DateTime, Utc};

/// WebKit / Windows FILETIME Epoch Offset from Unix Epoch (Jan 1, 1601 to Jan 1, 1970 UTC)
/// 11,644,473,600 seconds * 1,000,000 = 11,644,473,600_000_000 microseconds
pub const WEBKIT_EPOCH_OFFSET_MICROS: i64 = 11_644_473_600_000_000;

/// Converts a Chromium / WebKit timestamp (microseconds since 1601-01-01 00:00:00 UTC)
/// or a Unix timestamp into a formatted UTC String ("DD-MM-YYYY HH:MM:SS").
pub fn webkit_to_utc_string(raw_timestamp: i64) -> String {
    if raw_timestamp <= 0 {
        return Utc::now().format("%d-%m-%Y %H:%M:%S").to_string();
    }

    // 1. Chromium WebKit Microseconds Format (e.g. 13350000000000000)
    if raw_timestamp > 10_000_000_000_000_000 {
        let unix_micros = raw_timestamp - WEBKIT_EPOCH_OFFSET_MICROS;
        if unix_micros > 0 {
            let secs = unix_micros / 1_000_000;
            let nsecs = ((unix_micros % 1_000_000) * 1000) as u32;
            if let Some(dt) = DateTime::from_timestamp(secs, nsecs) {
                return dt.format("%d-%m-%Y %H:%M:%S").to_string();
            }
        }
    }

    // 2. Unix Milliseconds Format (e.g. 1705526400000)
    if raw_timestamp > 1_000_000_000_000 {
        let secs = raw_timestamp / 1000;
        let nsecs = ((raw_timestamp % 1000) * 1_000_000) as u32;
        if let Some(dt) = DateTime::from_timestamp(secs, nsecs) {
            return dt.format("%d-%m-%Y %H:%M:%S").to_string();
        }
    }

    // 3. Unix Seconds Format (e.g. 1705526400)
    if raw_timestamp > 100_000_000 {
        if let Some(dt) = DateTime::from_timestamp(raw_timestamp, 0) {
            return dt.format("%d-%m-%Y %H:%M:%S").to_string();
        }
    }

    Utc::now().format("%d-%m-%Y %H:%M:%S").to_string()
}
