//! Update-Prüfung – nur auf Wunsch (Knopf oder ausdrücklich eingeschaltete automatische Prüfung).
//!
//! Gefragt wird ausschließlich, wohin GitHub `…/releases/latest` weiterleitet; daraus ergibt sich die
//! neueste Versionsnummer. Es werden keine Daten über Nutzer oder Dateien gesendet. Für die Abfrage dient
//! das Systemprogramm `curl` (Linux, macOS, Windows 10/11), damit braucht Doclatch keine eigene
//! Netzwerk-Bibliothek. Heruntergeladen oder installiert wird nichts – nur die Download-Seite angeboten.

use std::process::{Command, Stdio};

pub const LATEST_URL: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/releases/latest");
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateState {
    Idle,
    Checking,
    UpToDate,
    Available { version: String, url: String },
    Failed(String),
}

/// Fragt GitHub ab (blockiert bis zu ~15 s – daher im Hintergrund aufrufen).
pub fn check() -> UpdateState {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let ua = concat!("doclatch/", env!("CARGO_PKG_VERSION"), " (update check)");
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "-I", "-o", null, "-w", "%{http_code} %{redirect_url}", "--max-time", "15", "-A", ua, LATEST_URL])
        .stdin(Stdio::null());
    #[cfg(windows)]
    {
        // GUI-Programm: kein Konsolenfenster für curl aufblitzen lassen
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match cmd.output() {
        Err(e) => UpdateState::Failed(format!("curl: {e}")),
        Ok(out) if !out.status.success() => {
            UpdateState::Failed(String::from_utf8_lossy(&out.stderr).trim().chars().take(200).collect())
        }
        Ok(out) => evaluate(&String::from_utf8_lossy(&out.stdout), CURRENT),
    }
}

/// Wertet `"<HTTP-Code> <Weiterleitung>"` aus.
fn evaluate(out: &str, current: &str) -> UpdateState {
    let (code, target) = out.trim().split_once(' ').unwrap_or((out.trim(), ""));
    if !code.starts_with('3') {
        return UpdateState::Failed(format!("HTTP {code}"));
    }
    match target.split_once("/releases/tag/") {
        Some((_, tag)) => {
            let version = tag.trim_start_matches(['v', 'V']).to_string();
            if is_newer(&version, current) {
                UpdateState::Available { version, url: target.to_string() }
            } else {
                UpdateState::UpToDate
            }
        }
        // Weiterleitung auf die Release-Übersicht: noch nichts veröffentlicht
        None => UpdateState::UpToDate,
    }
}

/// Vergleicht `a.b.c` numerisch; Zusätze wie `-beta` zählen als älter als die reine Version.
pub fn is_newer(remote: &str, local: &str) -> bool {
    fn parse(v: &str) -> (Vec<u64>, bool) {
        let (core, pre) = match v.split_once('-') {
            Some((c, _)) => (c, true),
            None => (v, false),
        };
        let mut n: Vec<u64> = core.split('.').map(|p| p.parse().unwrap_or(0)).collect();
        n.resize(3, 0);
        (n, pre)
    }
    let (r, r_pre) = parse(remote);
    let (l, l_pre) = parse(local);
    match r.cmp(&l) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => l_pre && !r_pre,
    }
}

/// Höchstens einmal täglich automatisch prüfen.
pub fn due(last_check_unix: u64, now_unix: u64) -> bool {
    now_unix.saturating_sub(last_check_unix) >= 24 * 60 * 60
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versionen_vergleichen() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(is_newer("0.2.0", "0.2.0-beta"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("0.2.0-beta", "0.2.0"));
    }

    #[test]
    fn github_antwort_auswerten() {
        let base = "https://github.com/Paderman/doclatch";
        assert_eq!(
            evaluate(&format!("302 {base}/releases/tag/v0.2.0"), "0.1.0"),
            UpdateState::Available { version: "0.2.0".into(), url: format!("{base}/releases/tag/v0.2.0") }
        );
        assert_eq!(evaluate(&format!("302 {base}/releases/tag/v0.1.0"), "0.1.0"), UpdateState::UpToDate);
        assert_eq!(evaluate(&format!("302 {base}/releases"), "0.1.0"), UpdateState::UpToDate);
        assert_eq!(evaluate("404 ", "0.1.0"), UpdateState::Failed("HTTP 404".into()));
    }

    #[test]
    fn taeglich_hoechstens_einmal() {
        assert!(due(0, 100_000));
        assert!(!due(100_000, 100_000 + 3600));
        assert!(due(100_000, 100_000 + 86_400));
    }

    /// Echte Abfrage bei GitHub (braucht Internet): `cargo test live_check -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn live_check() {
        let r = check();
        eprintln!("Ergebnis: {r:?}");
        assert!(!matches!(r, UpdateState::Failed(_)), "{r:?}");
    }
}
