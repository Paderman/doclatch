//! Dauerhafte Einstellungen (Theme, Sprache) und Erkennung des System-Themes.
//!
//! Gespeichert wird eine kleine Textdatei `settings.txt` (Zeilen `schlüssel=wert`) im üblichen
//! Konfigurationsordner des Betriebssystems – ohne zusätzliche Bibliotheken.

use crate::i18n::Lang;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ThemePref {
    #[default]
    Auto,
    Dark,
    Light,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LangPref {
    #[default]
    Auto,
    Fixed(Lang),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Settings {
    pub theme: ThemePref,
    pub lang: LangPref,
    /// Beim Start automatisch nach Updates suchen (Standard: aus)
    pub update_check: bool,
    /// Zeitpunkt der letzten Update-Prüfung (Unix-Sekunden)
    pub last_update_check: u64,
}

impl Settings {
    /// Liest das Textformat; Unbekanntes oder Kaputtes wird ignoriert (→ Standardwerte).
    pub fn parse(text: &str) -> Self {
        let mut s = Settings::default();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else { continue };
            match (key.trim(), value.trim()) {
                ("theme", "dark") => s.theme = ThemePref::Dark,
                ("theme", "light") => s.theme = ThemePref::Light,
                ("theme", _) => s.theme = ThemePref::Auto,
                ("lang", v) => s.lang = Lang::from_code(v).map_or(LangPref::Auto, LangPref::Fixed),
                ("update_check", v) => s.update_check = v == "on",
                ("last_update_check", v) => s.last_update_check = v.parse().unwrap_or(0),
                _ => {}
            }
        }
        s
    }

    pub fn serialize(&self) -> String {
        let theme = match self.theme {
            ThemePref::Auto => "auto",
            ThemePref::Dark => "dark",
            ThemePref::Light => "light",
        };
        let lang = match self.lang {
            LangPref::Auto => "auto",
            LangPref::Fixed(l) => l.code(),
        };
        let update = if self.update_check { "on" } else { "off" };
        format!("theme={theme}\nlang={lang}\nupdate_check={update}\nlast_update_check={}\n", self.last_update_check)
    }

    pub fn path() -> Option<PathBuf> {
        config_dir().map(|d| d.join("doclatch").join("settings.txt"))
    }

    pub fn load() -> Self {
        Self::path().and_then(|p| std::fs::read_to_string(p).ok()).map(|t| Self::parse(&t)).unwrap_or_default()
    }

    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path().ok_or_else(|| std::io::Error::other("kein Konfigurationsordner"))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, self.serialize())
    }

    pub fn effective_lang(&self) -> Lang {
        match self.lang {
            LangPref::Auto => Lang::detect(),
            LangPref::Fixed(l) => l,
        }
    }
}

/// Üblicher Konfigurationsordner je Betriebssystem.
fn config_dir() -> Option<PathBuf> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    #[cfg(windows)]
    return env("APPDATA");
    #[cfg(target_os = "macos")]
    return env("HOME").map(|h| h.join("Library/Application Support"));
    #[cfg(all(unix, not(target_os = "macos")))]
    return env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")));
    #[allow(unreachable_code)]
    None
}

/// Beobachtet unter Linux das Hell/Dunkel des Systems über das XDG-Desktop-Portal
/// (`org.freedesktop.appearance color-scheme`), da winit das unter X11 nicht meldet.
/// Unter Windows/macOS liefert egui das System-Theme selbst; dort bleibt dieser Wächter inaktiv.
#[derive(Clone)]
pub struct ThemeWatcher {
    /// 0 = unbekannt, 1 = dunkel, 2 = hell
    value: Arc<AtomicU8>,
    active: Arc<AtomicBool>,
}

impl ThemeWatcher {
    pub fn disabled() -> Self {
        Self { value: Arc::new(AtomicU8::new(0)), active: Arc::new(AtomicBool::new(false)) }
    }

    pub fn start(ctx: eframe::egui::Context) -> Self {
        let w = Self::disabled();
        #[cfg(target_os = "linux")]
        {
            let w2 = w.clone();
            std::thread::spawn(move || {
                loop {
                    if w2.active.load(Ordering::Relaxed) {
                        let v = match query_portal() {
                            Some(true) => 1,
                            Some(false) => 2,
                            None => 0,
                        };
                        if w2.value.swap(v, Ordering::Relaxed) != v {
                            ctx.request_repaint();
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_secs(3));
                }
            });
        }
        #[cfg(not(target_os = "linux"))]
        let _ = ctx;
        w
    }

    /// Nur abfragen, solange „Auto“ gewählt ist.
    pub fn set_active(&self, on: bool) {
        self.active.store(on, Ordering::Relaxed);
    }

    /// `Some(true)` = System ist dunkel, `Some(false)` = hell, `None` = unbekannt.
    pub fn is_dark(&self) -> Option<bool> {
        match self.value.load(Ordering::Relaxed) {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        }
    }
}

/// Fragt das Portal per `dbus-send` (Fallback `gdbus`) ab – beide sind auf Linux-Desktops vorhanden.
#[cfg(target_os = "linux")]
fn query_portal() -> Option<bool> {
    use std::process::{Command, Stdio};
    let dest = "org.freedesktop.portal.Desktop";
    let path = "/org/freedesktop/portal/desktop";
    let attempts: [Vec<String>; 2] = [
        [
            "dbus-send",
            "--session",
            "--print-reply=literal",
            "--reply-timeout=1000",
            &format!("--dest={dest}"),
            path,
            "org.freedesktop.portal.Settings.ReadOne",
            "string:org.freedesktop.appearance",
            "string:color-scheme",
        ]
        .map(String::from)
        .to_vec(),
        [
            "gdbus",
            "call",
            "--session",
            "--timeout=1",
            "--dest",
            dest,
            "--object-path",
            path,
            "--method",
            "org.freedesktop.portal.Settings.Read",
            "org.freedesktop.appearance",
            "color-scheme",
        ]
        .map(String::from)
        .to_vec(),
    ];
    for args in attempts {
        let Ok(out) = Command::new(&args[0]).args(&args[1..]).stderr(Stdio::null()).output() else { continue };
        if !out.status.success() {
            continue;
        }
        if let Some(v) = parse_color_scheme(&String::from_utf8_lossy(&out.stdout)) {
            return v;
        }
    }
    None
}

/// Portal-Wert: 1 = dunkel bevorzugt, 2 = hell bevorzugt, 0 = keine Vorgabe (→ hell, wie üblich).
/// Rückgabe `Some(None)`, wenn die Ausgabe nicht verständlich ist.
#[cfg(any(target_os = "linux", test))]
fn parse_color_scheme(out: &str) -> Option<Option<bool>> {
    let rest = out.split("uint32").nth(1)?;
    let digits: String = rest.trim_start().chars().take_while(char::is_ascii_digit).collect();
    match digits.parse::<u32>().ok()? {
        1 => Some(Some(true)),
        0 | 2 => Some(Some(false)),
        _ => Some(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn einstellungen_hin_und_zurueck() {
        let s = Settings {
            theme: ThemePref::Light,
            lang: LangPref::Fixed(Lang::Pl),
            update_check: true,
            last_update_check: 1_790_000_000,
        };
        assert_eq!(Settings::parse(&s.serialize()), s);
        assert_eq!(Settings::parse(&Settings::default().serialize()), Settings::default());
        // Kaputtes/Unbekanntes führt zu Standardwerten
        assert_eq!(Settings::parse("müll\ntheme=lila\nlang=xx\nfoo=bar"), Settings::default());
    }

    #[test]
    fn portal_ausgabe() {
        assert_eq!(parse_color_scheme("   uint32 1\n"), Some(Some(true)));
        assert_eq!(parse_color_scheme("(<<uint32 2>>,)\n"), Some(Some(false)));
        assert_eq!(parse_color_scheme("variant       uint32 0"), Some(Some(false)));
        assert_eq!(parse_color_scheme("Fehler"), None);
    }
}
