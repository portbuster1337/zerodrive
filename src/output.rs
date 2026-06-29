use owo_colors::OwoColorize;

pub fn success(msg: impl AsRef<str>) {
    let no_color = std::env::var("NO_COLOR").is_ok();
    if no_color {
        eprintln!("✓ {}", msg.as_ref());
    } else {
        eprintln!("{} {}", "✓".green().bold(), msg.as_ref());
    }
}

pub fn error(msg: impl AsRef<str>) {
    let no_color = std::env::var("NO_COLOR").is_ok();
    if no_color {
        eprintln!("✗ {}", msg.as_ref());
    } else {
        eprintln!("{} {}", "✗".red().bold(), msg.as_ref());
    }
}

pub fn info(msg: impl AsRef<str>) {
    let no_color = std::env::var("NO_COLOR").is_ok();
    if no_color {
        eprintln!("• {}", msg.as_ref());
    } else {
        eprintln!("{} {}", "•".cyan().bold(), msg.as_ref());
    }
}

/// Format bytes into a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut size = bytes as f64;
    let mut unit = UNITS[0];
    for u in UNITS.iter().skip(1) {
        if size >= 1024.0 {
            size /= 1024.0;
            unit = u;
        } else {
            break;
        }
    }
    format!("{:.1} {}", size, unit)
}
