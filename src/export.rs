//! Passwörter erzeugen und als Liste (TXT oder CSV) exportieren.

use std::path::{Path, PathBuf};

/// Zeichen ohne leicht verwechselbare (0/O, 1/l/I) und ohne solche, die auf manchen
/// Tastaturbelegungen schwer zu tippen sind.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!#%+=?@";

/// Länge erzeugter Passwörter (bei 66 Zeichen rund 120 Bit Zufall).
pub const GENERATED_LEN: usize = 20;

/// Erzeugt ein zufälliges Passwort aus [`ALPHABET`] (gleichverteilt per Verwerfungsmethode).
/// Das erste Zeichen ist immer ein Buchstabe oder eine Ziffer – ein führendes `=`, `+`, `-` oder
/// `@` würde beim Öffnen einer exportierten CSV in Tabellenprogrammen als Formel gelten.
pub fn generate_password() -> Result<String, getrandom::Error> {
    loop {
        let pw = random_chars()?;
        if pw.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            return Ok(pw);
        }
    }
}

fn random_chars() -> Result<String, getrandom::Error> {
    // Größtes Vielfaches der Alphabetlänge unter 256 – Bytes darüber werden verworfen.
    let limit = (256 / ALPHABET.len() * ALPHABET.len()) as u8;
    let mut out = String::with_capacity(GENERATED_LEN);
    let mut buf = [0u8; 64];
    while out.len() < GENERATED_LEN {
        getrandom::fill(&mut buf)?;
        for &b in &buf {
            if b < limit && out.len() < GENERATED_LEN {
                out.push(ALPHABET[usize::from(b) % ALPHABET.len()] as char);
            }
        }
    }
    Ok(out)
}

/// Ein geschütztes Ergebnis mit den dafür verwendeten Passwörtern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub file: PathBuf,
    /// Öffnen-Passwort (leer = keins)
    pub open: String,
    /// Selbst gewähltes Rechte-Passwort; `None` = zufällig erzeugt und nirgends gespeichert
    pub owner: Option<String>,
}

impl Record {
    /// Enthält der Eintrag überhaupt ein Passwort, das sich aufzuheben lohnt?
    pub fn has_password(&self) -> bool {
        !self.open.is_empty() || self.owner.is_some()
    }
}

/// Bezeichnungen in der Sprache der Oberfläche.
pub struct Labels<'a> {
    pub title: &'a str,
    pub created: &'a str,
    pub warning: &'a str,
    pub file: &'a str,
    pub open: &'a str,
    pub owner: &'a str,
}

/// Gut lesbare Textliste.
pub fn to_txt(records: &[Record], l: &Labels, created: &str) -> String {
    let mut s = format!("{}\n{}: {created}\n{}\n", l.title, l.created, l.warning);
    for r in records.iter().filter(|r| r.has_password()) {
        s.push_str(&format!("\n{}: {}\n", l.file, r.file.display()));
        if !r.open.is_empty() {
            s.push_str(&format!("{}: {}\n", l.open, r.open));
        }
        if let Some(o) = &r.owner {
            s.push_str(&format!("{}: {o}\n", l.owner));
        }
    }
    s
}

/// CSV mit den Spalten `Title,Username,Password,URL,Notes` – lässt sich in gängige
/// Passwortmanager (z. B. KeePassXC, Bitwarden) importieren. Je Passwort eine Zeile.
pub fn to_csv(records: &[Record], l: &Labels) -> String {
    let mut s = String::from("Title,Username,Password,URL,Notes\r\n");
    for r in records {
        let name = r.file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let path = r.file.display().to_string();
        let rows = [(l.open, Some(r.open.as_str()).filter(|p| !p.is_empty())), (l.owner, r.owner.as_deref())];
        for (label, pw) in rows {
            if let Some(pw) = pw {
                let fields = [format!("{name} ({label})"), String::new(), pw.to_string(), String::new(), path.clone()];
                let line: Vec<String> = fields.iter().map(|f| csv_field(f)).collect();
                s.push_str(&line.join(","));
                s.push_str("\r\n");
            }
        }
    }
    s
}

/// Feld immer in Anführungszeichen; enthaltene Anführungszeichen werden verdoppelt.
/// Ein führendes `=`, `+`, `-` oder `@` könnte in Tabellenprogrammen als Formel gelten –
/// Passwörter bleiben trotzdem unverändert, damit der Import in Passwortmanager stimmt.
fn csv_field(f: &str) -> String {
    format!("\"{}\"", f.replace('"', "\"\""))
}

/// Datum und Uhrzeit (UTC) im Format `2026-11-19 14:03 UTC` – ohne zusätzliche Abhängigkeit.
pub fn now_utc() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format_utc(secs)
}

fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let (h, m) = ((secs % 86_400) / 3600, (secs % 3600) / 60);
    // Kalenderdatum aus Tagen seit 1970 (Algorithmus von Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

/// Schreibt die Liste. Unter Unix nur für den Besitzer lesbar (0600).
pub fn write(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()
}

/// CSV, wenn die Endung `.csv` lautet, sonst Text.
pub fn is_csv(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("csv"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const L: Labels = Labels {
        title: "Doclatch – passwords",
        created: "Created",
        warning: "Not encrypted.",
        file: "File",
        open: "Open password",
        owner: "Permissions password",
    };

    fn records() -> Vec<Record> {
        vec![
            Record { file: "/a/vertrag_protected.pdf".into(), open: "ab\"c".into(), owner: None },
            Record { file: "/a/b_protected.pdf".into(), open: String::new(), owner: Some("chef".into()) },
            Record { file: "/a/leer.pdf".into(), open: String::new(), owner: None },
        ]
    }

    #[test]
    fn passwort_generator() {
        let a = generate_password().unwrap();
        let b = generate_password().unwrap();
        assert_eq!(a.len(), GENERATED_LEN);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| ALPHABET.contains(&c)));
        // keine verwechselbaren Zeichen
        let many: String = (0..50).map(|_| generate_password().unwrap()).collect();
        assert!(!many.contains(['0', 'O', '1', 'l', 'I']));
        assert!((0..50).all(|_| generate_password().unwrap().starts_with(|c: char| c.is_ascii_alphanumeric())));
    }

    #[test]
    fn text_export() {
        let s = to_txt(&records(), &L, "2026-11-19 14:03 UTC");
        assert_eq!(
            s,
            "Doclatch – passwords\nCreated: 2026-11-19 14:03 UTC\nNot encrypted.\n\n\
             File: /a/vertrag_protected.pdf\nOpen password: ab\"c\n\n\
             File: /a/b_protected.pdf\nPermissions password: chef\n"
        );
    }

    #[test]
    fn csv_export() {
        let s = to_csv(&records(), &L);
        assert_eq!(
            s,
            "Title,Username,Password,URL,Notes\r\n\
             \"vertrag_protected.pdf (Open password)\",\"\",\"ab\"\"c\",\"\",\"/a/vertrag_protected.pdf\"\r\n\
             \"b_protected.pdf (Permissions password)\",\"\",\"chef\",\"\",\"/a/b_protected.pdf\"\r\n"
        );
        assert!(is_csv(Path::new("x.CSV")) && !is_csv(Path::new("x.txt")));
    }

    #[test]
    fn datum() {
        assert_eq!(format_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(format_utc(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(format_utc(1_795_100_580), "2026-11-19 15:03 UTC");
    }

    #[cfg(unix)]
    #[test]
    fn datei_nur_fuer_besitzer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::core::tests::tmpdir("export");
        let p = dir.join("pw.txt");
        write(&p, "x").unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(dir).ok();
    }
}
