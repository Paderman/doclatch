//! Kernlogik: PDF-Schutz erkennen und entfernen (reines Rust, plattformunabhängig).

pub use lopdf::Permissions;
use lopdf::{Document, LoadOptions};
use std::fmt;
use std::path::{Path, PathBuf};

/// Schutzstatus einer PDF-Datei.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Nicht verschlüsselt – nichts zu tun.
    None,
    /// Nur Rechte-Einschränkungen (Drucken/Kopieren/…), öffnen ohne Passwort möglich.
    RestrictionsOnly,
    /// Zum Öffnen ist ein Passwort nötig.
    PasswordRequired,
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protection::None => "not protected",
            Protection::RestrictionsOnly => "restrictions only",
            Protection::PasswordRequired => "password required",
        })
    }
}

#[derive(Debug)]
pub enum UnlockError {
    WrongPassword,
    PasswordMissing,
    NotEncrypted,
    Pdf(String),
    Io(std::io::Error),
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnlockError::WrongPassword => f.write_str("wrong password"),
            UnlockError::PasswordMissing => f.write_str("password required"),
            UnlockError::NotEncrypted => f.write_str("file is not protected"),
            UnlockError::Pdf(e) => write!(f, "PDF error: {e}"),
            UnlockError::Io(e) => write!(f, "file error: {e}"),
        }
    }
}

impl std::error::Error for UnlockError {}

impl From<std::io::Error> for UnlockError {
    fn from(e: std::io::Error) -> Self {
        UnlockError::Io(e)
    }
}

fn map_lopdf(e: lopdf::Error) -> UnlockError {
    match e {
        lopdf::Error::InvalidPassword => UnlockError::WrongPassword,
        lopdf::Error::IO(io) => UnlockError::Io(io),
        other => UnlockError::Pdf(other.to_string()),
    }
}

fn load(bytes: &[u8], password: Option<&str>) -> Result<Document, UnlockError> {
    let options = match password {
        Some(p) if !p.is_empty() => LoadOptions::with_password(p),
        _ => LoadOptions::default(),
    };
    Document::load_mem_with_options(bytes, options).map_err(map_lopdf)
}

/// Ergebnis der Prüfung einer Datei.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inspection {
    pub protection: Protection,
    /// Gesetzte Rechte (nur bei verschlüsselten Dateien und wenn lesbar).
    pub permissions: Option<Permissions>,
}

/// Ermittelt Schutzstatus und Berechtigungen einer Datei.
pub fn inspect(path: &Path) -> Result<Inspection, UnlockError> {
    let bytes = std::fs::read(path)?;
    let doc = load(&bytes, None)?;
    Ok(if doc.is_encrypted() {
        // lopdf konnte mit leerem Benutzerpasswort nicht entschlüsseln.
        // Der /P-Eintrag des Encrypt-Wörterbuchs ist auch ohne Passwort lesbar.
        let permissions = doc
            .get_encrypted()
            .ok()
            .and_then(|d| d.get(b"P").ok())
            .and_then(|p| p.as_i64().ok())
            .map(|p| Permissions::from_bits_truncate(u64::from(p as i32 as u32)));
        Inspection { protection: Protection::PasswordRequired, permissions }
    } else if let Some(state) = &doc.encryption_state {
        Inspection { protection: Protection::RestrictionsOnly, permissions: Some(state.permissions()) }
    } else {
        Inspection { protection: Protection::None, permissions: None }
    })
}

/// Standard-Zielpfad: `name_unlocked.pdf` im selben Ordner (oder in `out_dir`).
pub fn default_output(input: &Path, out_dir: Option<&Path>) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("document");
    let dir = out_dir.map(Path::to_path_buf).or_else(|| input.parent().map(Path::to_path_buf)).unwrap_or_default();
    dir.join(format!("{stem}_unlocked.pdf"))
}

/// Lädt eine Datei vollständig entschlüsselt. Liefert auch, wie sie vorher geschützt war.
fn open_plain(bytes: &[u8], password: Option<&str>) -> Result<(Document, Protection), UnlockError> {
    // Erst ohne Passwort versuchen (deckt reine Rechte-Einschränkungen ab).
    let mut doc = load(bytes, None)?;
    let protection = if doc.is_encrypted() {
        match password {
            Some(p) if !p.is_empty() => doc = load(bytes, Some(p))?,
            _ => return Err(UnlockError::PasswordMissing),
        }
        if doc.is_encrypted() {
            return Err(UnlockError::WrongPassword);
        }
        Protection::PasswordRequired
    } else if doc.was_encrypted() {
        Protection::RestrictionsOnly
    } else {
        Protection::None
    };
    // Verschlüsselungs-Wörterbuch entfernen, damit beim Speichern nichts (alt) verschlüsselt wird.
    doc.encryption_state = None;
    if let Some(lopdf::Object::Reference(id)) = doc.trailer.remove(b"Encrypt") {
        doc.objects.remove(&id);
    }
    Ok((doc, protection))
}

fn save(doc: &mut Document, output: &Path, size_hint: usize) -> Result<(), UnlockError> {
    let mut buf = Vec::with_capacity(size_hint);
    doc.save_to(&mut buf)?;
    write_atomic(output, &buf)?;
    Ok(())
}

/// Entfernt Verschlüsselung und Einschränkungen und schreibt das Ergebnis nach `output`.
/// `output` darf gleich `input` sein – dann wird atomar über eine Temp-Datei ersetzt.
pub fn unlock(input: &Path, output: &Path, password: Option<&str>) -> Result<Protection, UnlockError> {
    let bytes = std::fs::read(input)?;
    let (mut doc, protection) = open_plain(&bytes, password)?;
    if protection == Protection::None {
        return Err(UnlockError::NotEncrypted);
    }
    save(&mut doc, output, bytes.len())?;
    Ok(protection)
}

/// Einstellungen für den Schutz-Modus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectOptions {
    /// Passwort zum Öffnen (leer = Datei öffnet sich ohne Passwort, nur Einschränkungen).
    pub open_password: String,
    /// Passwort für volle Rechte (leer = zufällig, damit niemand darüber alle Rechte bekommt).
    pub owner_password: String,
    /// Erlaubte Aktionen.
    pub permissions: Permissions,
}

impl ProtectOptions {
    /// Gibt es überhaupt etwas zu schützen?
    pub fn is_effective(&self) -> bool {
        !self.open_password.is_empty() || !self.permissions.contains(ALL_PERMISSIONS)
    }
}

/// Die acht Rechte, die PDF-Programme anzeigen.
pub const ALL_PERMISSIONS: Permissions = Permissions::PRINTABLE
    .union(Permissions::PRINTABLE_IN_HIGH_QUALITY)
    .union(Permissions::MODIFIABLE)
    .union(Permissions::COPYABLE)
    .union(Permissions::ANNOTABLE)
    .union(Permissions::FILLABLE)
    .union(Permissions::COPYABLE_FOR_ACCESSIBILITY)
    .union(Permissions::ASSEMBLABLE);

/// Standard-Zielpfad im Schutz-Modus: `name_protected.pdf`.
pub fn protected_output(input: &Path, out_dir: Option<&Path>) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("document");
    let dir = out_dir.map(Path::to_path_buf).unwrap_or_else(|| input.parent().unwrap_or(Path::new(".")).to_path_buf());
    dir.join(format!("{stem}_protected.pdf"))
}

/// Verschlüsselt eine Datei mit AES-256 (PDF 2.0, Revision 6) und den gewählten Rechten.
/// Eine bereits geschützte Datei wird vorher entschlüsselt (`current_password`, falls nötig).
pub fn protect(
    input: &Path,
    output: &Path,
    opts: &ProtectOptions,
    current_password: Option<&str>,
) -> Result<(), UnlockError> {
    use lopdf::encryption::crypt_filters::{Aes256CryptFilter, CryptFilter};
    use lopdf::{EncryptionState, EncryptionVersion};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    let bytes = std::fs::read(input)?;
    let (mut doc, _) = open_plain(&bytes, current_password)?;

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| UnlockError::Pdf(format!("random: {e}")))?;
    let owner = if opts.owner_password.is_empty() { random_password()? } else { opts.owner_password.clone() };
    let filter: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
    let state = EncryptionState::try_from(EncryptionVersion::V5 {
        encrypt_metadata: true,
        crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), filter)]),
        file_encryption_key: &key,
        stream_filter: b"StdCF".to_vec(),
        string_filter: b"StdCF".to_vec(),
        owner_password: &owner,
        user_password: &opts.open_password,
        permissions: opts.permissions & ALL_PERMISSIONS,
    })
    .map_err(|e| UnlockError::Pdf(e.to_string()))?;
    // AES-256 gibt es ab PDF 1.7 (Erweiterung) bzw. 2.0
    if doc.version.as_str() < "1.7" {
        doc.version = "1.7".into();
    }
    doc.encrypt(&state).map_err(map_lopdf)?;
    save(&mut doc, output, bytes.len())
}

fn random_password() -> Result<String, UnlockError> {
    let mut b = [0u8; 24];
    getrandom::fill(&mut b).map_err(|e| UnlockError::Pdf(format!("random: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn write_atomic(target: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("out.pdf");
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, target).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use lopdf::encryption::crypt_filters::{Aes128CryptFilter, Aes256CryptFilter, CryptFilter};
    use lopdf::{EncryptionState, EncryptionVersion, Object, Permissions, Stream, dictionary};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const TEXT: &[u8] = b"BT /F1 24 Tf 72 720 Td (Hallo geheime Welt) Tj ET";

    fn sample() -> Document {
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let font_id = doc.add_object(dictionary! {
            "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
        });
        let content_id = doc.add_object(Stream::new(dictionary! {}, TEXT.to_vec()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let id = Object::string_literal(b"0123456789abcdef".to_vec());
        doc.trailer.set("ID", vec![id.clone(), id]);
        doc
    }

    pub(crate) fn encrypted_file(dir: &Path, name: &str, version: u8, user: &str, owner: &str) -> PathBuf {
        encrypted_file_with(dir, name, version, user, owner, Permissions::empty())
    }

    pub(crate) fn encrypted_file_with(
        dir: &Path,
        name: &str,
        version: u8,
        user: &str,
        owner: &str,
        perms: Permissions,
    ) -> PathBuf {
        let mut doc = sample();
        let key = [7u8; 32];
        let aes128: Arc<dyn CryptFilter> = Arc::new(Aes128CryptFilter);
        let aes256: Arc<dyn CryptFilter> = Arc::new(Aes256CryptFilter);
        let v = match version {
            2 => EncryptionVersion::V2 {
                document: &doc,
                owner_password: owner,
                user_password: user,
                key_length: 128,
                permissions: perms,
            },
            4 => EncryptionVersion::V4 {
                document: &doc,
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes128)]),
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: owner,
                user_password: user,
                permissions: perms,
            },
            _ => EncryptionVersion::V5 {
                encrypt_metadata: true,
                crypt_filters: BTreeMap::from([(b"StdCF".to_vec(), aes256)]),
                file_encryption_key: &key,
                stream_filter: b"StdCF".to_vec(),
                string_filter: b"StdCF".to_vec(),
                owner_password: owner,
                user_password: user,
                permissions: perms,
            },
        };
        let state = EncryptionState::try_from(v).unwrap();
        doc.encrypt(&state).unwrap();
        let path = dir.join(name);
        doc.save(&path).unwrap();
        path
    }

    pub(crate) fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("doclatch-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn assert_plain(path: &Path) {
        let doc = Document::load(path).unwrap();
        assert!(!doc.is_encrypted() && !doc.was_encrypted());
        let raw = std::fs::read(path).unwrap();
        assert!(raw.windows(TEXT.len()).any(|w| w == TEXT), "Klartext fehlt");
    }

    #[test]
    fn user_password_all_versions() {
        let dir = tmpdir("user");
        for v in [2u8, 4, 5] {
            let p = encrypted_file(&dir, &format!("v{v}.pdf"), v, "geheim", "owner");
            assert_eq!(inspect(&p).unwrap().protection, Protection::PasswordRequired);
            assert!(matches!(unlock(&p, &dir.join("x.pdf"), None), Err(UnlockError::PasswordMissing)));
            assert!(matches!(unlock(&p, &dir.join("x.pdf"), Some("falsch")), Err(UnlockError::WrongPassword)));
            let out = default_output(&p, None);
            assert_eq!(unlock(&p, &out, Some("geheim")).unwrap(), Protection::PasswordRequired);
            assert_plain(&out);
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn restrictions_only() {
        let dir = tmpdir("restr");
        for v in [2u8, 4, 5] {
            let p = encrypted_file(&dir, &format!("r{v}.pdf"), v, "", "owner");
            assert_eq!(inspect(&p).unwrap().protection, Protection::RestrictionsOnly);
            // in-place überschreiben
            assert_eq!(unlock(&p, &p, None).unwrap(), Protection::RestrictionsOnly);
            assert_plain(&p);
            assert_eq!(inspect(&p).unwrap().protection, Protection::None);
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn berechtigungen_werden_gelesen() {
        let dir = tmpdir("perms");
        let perms = Permissions::PRINTABLE | Permissions::COPYABLE_FOR_ACCESSIBILITY;
        for v in [2u8, 4, 5] {
            // nur Einschränkungen: Rechte aus dem Entschlüsselungszustand
            let p = encrypted_file_with(&dir, &format!("r{v}.pdf"), v, "", "owner", perms);
            let i = inspect(&p).unwrap();
            assert_eq!(i.protection, Protection::RestrictionsOnly);
            let got = i.permissions.unwrap();
            assert!(
                got.contains(perms) && !got.contains(Permissions::COPYABLE) && !got.contains(Permissions::MODIFIABLE)
            );
            // mit Öffnen-Passwort: Rechte direkt aus /P
            let p = encrypted_file_with(&dir, &format!("u{v}.pdf"), v, "geheim", "owner", perms);
            let i = inspect(&p).unwrap();
            assert_eq!(i.protection, Protection::PasswordRequired);
            let got = i.permissions.unwrap();
            assert!(got.contains(perms) && !got.contains(Permissions::COPYABLE));
        }
        let plain = dir.join("plain.pdf");
        sample().save(&plain).unwrap();
        assert_eq!(inspect(&plain).unwrap(), Inspection { protection: Protection::None, permissions: None });
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn schuetzen_und_wieder_entsperren() {
        let dir = tmpdir("protect");
        let plain = dir.join("plain.pdf");
        sample().save(&plain).unwrap();

        // Öffnen-Passwort + eingeschränkte Rechte
        let perms = Permissions::PRINTABLE | Permissions::COPYABLE_FOR_ACCESSIBILITY;
        let opts =
            ProtectOptions { open_password: "Grüße1".into(), owner_password: String::new(), permissions: perms };
        assert!(opts.is_effective());
        let out = protected_output(&plain, None);
        protect(&plain, &out, &opts, None).unwrap();
        let raw = std::fs::read(&out).unwrap();
        assert!(!raw.windows(TEXT.len()).any(|w| w == TEXT), "Inhalt muss verschlüsselt sein");
        let i = inspect(&out).unwrap();
        assert_eq!(i.protection, Protection::PasswordRequired);
        let got = i.permissions.unwrap();
        assert!(got.contains(perms) && !got.contains(Permissions::COPYABLE) && !got.contains(Permissions::MODIFIABLE));
        assert!(matches!(unlock(&out, &dir.join("x.pdf"), Some("falsch")), Err(UnlockError::WrongPassword)));
        let back = dir.join("back.pdf");
        unlock(&out, &back, Some("Grüße1")).unwrap();
        assert_plain(&back);

        // Nur Einschränkungen: öffnet ohne Passwort
        let opts = ProtectOptions {
            open_password: String::new(),
            owner_password: "chef".into(),
            permissions: Permissions::empty(),
        };
        protect(&plain, &out, &opts, None).unwrap();
        assert_eq!(inspect(&out).unwrap().protection, Protection::RestrictionsOnly);

        // Bereits geschützte Datei neu schützen (braucht das alte Passwort)
        let locked = encrypted_file(&dir, "locked.pdf", 4, "alt", "owner");
        let opts =
            ProtectOptions { open_password: "neu".into(), owner_password: String::new(), permissions: ALL_PERMISSIONS };
        assert!(matches!(protect(&locked, &out, &opts, None), Err(UnlockError::PasswordMissing)));
        protect(&locked, &out, &opts, Some("alt")).unwrap();
        unlock(&out, &back, Some("neu")).unwrap();
        assert_plain(&back);

        // Nichts zu schützen
        let none = ProtectOptions {
            open_password: String::new(),
            owner_password: String::new(),
            permissions: ALL_PERMISSIONS,
        };
        assert!(!none.is_effective());
        std::fs::remove_dir_all(dir).ok();
    }
}
