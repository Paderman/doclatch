//! Übergaben an das Betriebssystem: Datei im Dateimanager zeigen, Webseite im Browser öffnen.
//!
//! „Im Ordner anzeigen“ öffnet den Dateimanager und markiert die Datei.
//!
//! - Linux: D-Bus `org.freedesktop.FileManager1.ShowItems` (Dolphin, Nautilus, Nemo, Caja, Thunar …),
//!   aufgerufen über `dbus-send` bzw. `gdbus`; Rückfall: Ordner mit `xdg-open` öffnen (ohne Markierung).
//! - Windows: `explorer /select,"…"`
//! - macOS: `open -R …`

use std::path::{Path, PathBuf};

/// Läuft im Hintergrund, damit die Oberfläche nie wartet.
pub fn reveal(path: &Path) {
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        if let Err(e) = reveal_blocking(&p) {
            eprintln!("Could not open file manager: {e}");
        }
    });
}

#[cfg(all(unix, not(target_os = "macos")))]
fn reveal_blocking(p: &Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let abs = std::fs::canonicalize(p)?;
    let uri = file_uri(&abs);
    let quiet =
        |c: &mut Command| c.stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false);
    let ok = quiet(Command::new("dbus-send").args([
        "--session",
        "--print-reply",
        "--dest=org.freedesktop.FileManager1",
        "--type=method_call",
        "/org/freedesktop/FileManager1",
        "org.freedesktop.FileManager1.ShowItems",
        &format!("array:string:{uri}"),
        "string:",
    ])) || quiet(Command::new("gdbus").args([
        "call",
        "--session",
        "--dest",
        "org.freedesktop.FileManager1",
        "--object-path",
        "/org/freedesktop/FileManager1",
        "--method",
        "org.freedesktop.FileManager1.ShowItems",
        &format!("['{uri}']"),
        "",
    ]));
    if ok {
        return Ok(());
    }
    let dir = abs.parent().map(Path::to_path_buf).unwrap_or(abs);
    Command::new("xdg-open").arg(dir).stdout(Stdio::null()).stderr(Stdio::null()).spawn().map(|_| ())
}

#[cfg(target_os = "macos")]
fn reveal_blocking(p: &Path) -> std::io::Result<()> {
    std::process::Command::new("open").arg("-R").arg(p).spawn().map(|_| ())
}

#[cfg(windows)]
fn reveal_blocking(p: &Path) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    let abs = std::fs::canonicalize(p)?;
    // canonicalize liefert \\?\C:\… – das versteht der Explorer nicht
    let s = abs.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    // Explorer erwartet genau diese Schreibweise; raw_arg verhindert zusätzliches Quoting.
    std::process::Command::new("explorer").raw_arg(format!("/select,\"{s}\"")).spawn().map(|_| ())
}

/// Öffnet eine Webseite im Standardbrowser (nur `https://`-Adressen).
pub fn open_url(url: &str) {
    if !url.starts_with("https://") {
        return;
    }
    let url = url.to_string();
    std::thread::spawn(move || {
        #[cfg(all(unix, not(target_os = "macos")))]
        let r = std::process::Command::new("xdg-open").arg(&url).spawn();
        #[cfg(target_os = "macos")]
        let r = std::process::Command::new("open").arg(&url).spawn();
        #[cfg(windows)]
        let r = std::process::Command::new("explorer").arg(&url).spawn();
        if let Err(e) = r {
            eprintln!("Could not open browser: {e}");
        }
    });
}

/// `file://`-URI mit Prozent-Kodierung (Leerzeichen, Umlaute, Sonderzeichen).
#[cfg(any(all(unix, not(target_os = "macos")), all(test, unix)))]
fn file_uri(abs: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let bytes = abs.as_os_str().as_bytes().to_vec();
    let mut out = String::from("file://");
    for b in bytes {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Welche Datei angezeigt wird: das Ergebnis, falls vorhanden, sonst das Original.
pub fn target_for(original: &Path, result: Option<&PathBuf>) -> PathBuf {
    result.filter(|p| p.exists()).cloned().unwrap_or_else(|| original.to_path_buf())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn uri_kodierung() {
        assert_eq!(
            file_uri(Path::new("/tmp/a b/Grüße & 100%.pdf")),
            "file:///tmp/a%20b/Gr%C3%BC%C3%9Fe%20%26%20100%25.pdf"
        );
        assert_eq!(file_uri(Path::new("/x/it's.pdf")), "file:///x/it%27s.pdf");
    }
}
