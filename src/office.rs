//! Office-Dokumente (OOXML: DOCX/XLSX/PPTX, ODF: ODT/ODS/ODP): Bearbeitungs-, Blatt- und
//! Strukturschutz erkennen und entfernen.
//!
//! Dieser Schutz ist keine Verschlüsselung – der Inhalt liegt im Klartext vor, das Programm
//! verweigert nur das Bearbeiten. Entfernt werden ausschließlich die Schutz-Einträge in den
//! XML-Teilen; alle übrigen ZIP-Einträge werden unverändert (roh) übernommen.

use crate::core::{Inspection, Protection, UnlockError};
use quick_xml::Reader;
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesStart, BytesText, Event};
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::path::Path;

/// Paketformat eines Office-Dokuments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Office Open XML (Microsoft Office).
    Ooxml,
    /// OpenDocument (LibreOffice u. a.).
    Odf,
}

const OOXML_EXT: &[&str] =
    &["docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "pptx", "pptm", "potx", "potm", "ppsx", "ppsm"];
const ODF_EXT: &[&str] = &["odt", "ott", "ods", "ots", "odp", "otp", "odg", "otg", "odm"];

/// Dokumentarten für die Filter im Dateidialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Text,
    Spreadsheet,
    Presentation,
    Drawing,
}

/// Endungen je Dokumentart (Microsoft und OpenDocument gemeinsam).
pub const CATEGORIES: [(Category, &[&str]); 4] = [
    (Category::Text, &["docx", "docm", "dotx", "dotm", "odt", "ott", "odm"]),
    (Category::Spreadsheet, &["xlsx", "xlsm", "xltx", "xltm", "ods", "ots"]),
    (Category::Presentation, &["pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "odp", "otp"]),
    (Category::Drawing, &["odg", "otg"]),
];

/// Alle unterstützten Office-Endungen (für Dateidialoge und Drag & Drop).
pub fn extensions() -> impl Iterator<Item = &'static str> {
    OOXML_EXT.iter().chain(ODF_EXT).copied()
}

/// Erkennt das Format an der Dateiendung.
pub fn format_of(path: &Path) -> Option<Format> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    if OOXML_EXT.contains(&ext.as_str()) {
        Some(Format::Ooxml)
    } else if ODF_EXT.contains(&ext.as_str()) {
        Some(Format::Odf)
    } else {
        None
    }
}

/// Gefundene Schutzarten (kleine Bitmenge, damit [`Inspection`] `Copy` bleibt).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Locks(u8);

impl Locks {
    /// Dokument nur eingeschränkt bearbeitbar (Word: „Bearbeitung einschränken“).
    pub const EDITING: Locks = Locks(1);
    /// Kennwort zum Ändern bzw. Empfehlung, schreibgeschützt zu öffnen.
    pub const READ_ONLY: Locks = Locks(1 << 1);
    /// Arbeitsmappen-Struktur geschützt (Blätter einfügen/löschen/umbenennen).
    pub const STRUCTURE: Locks = Locks(1 << 2);
    /// Einzelne Tabellenblätter geschützt.
    pub const SHEETS: Locks = Locks(1 << 3);
    /// Geschützte Bereiche im Text (ODF-Bereiche).
    pub const SECTIONS: Locks = Locks(1 << 4);
    /// Änderungsverfolgung mit Kennwort geschützt.
    pub const TRACKED_CHANGES: Locks = Locks(1 << 5);

    pub const ALL: [Locks; 6] =
        [Self::EDITING, Self::READ_ONLY, Self::STRUCTURE, Self::SHEETS, Self::SECTIONS, Self::TRACKED_CHANGES];

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn contains(self, other: Locks) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn insert(&mut self, other: Locks) {
        self.0 |= other.0;
    }
    /// Die einzelnen gesetzten Schutzarten.
    pub fn iter(self) -> impl Iterator<Item = Locks> {
        Self::ALL.into_iter().filter(move |l| self.contains(*l))
    }
}

impl fmt::Display for Locks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self
            .iter()
            .map(|l| match l {
                Locks::EDITING => "editing restriction",
                Locks::READ_ONLY => "password to modify / read-only recommendation",
                Locks::STRUCTURE => "workbook structure protection",
                Locks::SHEETS => "sheet protection",
                Locks::SECTIONS => "protected sections",
                _ => "protected change tracking",
            })
            .collect();
        f.write_str(&names.join(", "))
    }
}

/// Obergrenze für einen entpackten XML-Teil (Schutz vor ZIP-Bomben).
const MAX_PART: u64 = 512 * 1024 * 1024;

/// Erste Bytes eines OLE-Containers: so speichert Office passwortverschlüsselte OOXML-Dateien.
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

fn zip_err(e: zip::result::ZipError) -> UnlockError {
    match e {
        zip::result::ZipError::Io(io) => UnlockError::Io(io),
        other => UnlockError::Document(other.to_string()),
    }
}

fn xml_err(part: &str, e: impl fmt::Display) -> UnlockError {
    UnlockError::Document(format!("{part}: {e}"))
}

/// Ergebnis einer Analyse: gefundene Schutzarten und – falls gewünscht – die geänderten Teile.
struct Scan {
    locks: Locks,
    signed: bool,
    encrypted: bool,
    /// (Index im Archiv, neuer Inhalt)
    changed: Vec<(usize, Vec<u8>)>,
}

/// Prüft, ob ein Teil überhaupt Schutz-Einträge enthalten kann (spart das Parsen großer Blätter).
fn candidate(format: Format, name: &str) -> Option<&'static [&'static [u8]]> {
    match format {
        Format::Ooxml if !name.ends_with(".xml") => None,
        Format::Ooxml if name.starts_with("word/") => Some(&[b"documentProtection", b"writeProtection"]),
        Format::Ooxml if name.starts_with("xl/") => Some(&[b"sheetProtection", b"workbookProtection", b"fileSharing"]),
        Format::Ooxml if name.starts_with("ppt/") => Some(&[b"modifyVerifier"]),
        Format::Ooxml => None,
        Format::Odf if name == "content.xml" || name == "styles.xml" => {
            Some(&[b"table:protected", b"table:structure-protected", b"text:protected"])
        }
        Format::Odf if name == "settings.xml" => {
            Some(&[b"LoadReadonly", b"RedlineProtectionKey", b"ModifyPasswordInfo"])
        }
        Format::Odf => None,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn scan(bytes: &[u8], format: Format) -> Result<Scan, UnlockError> {
    let mut result = Scan { locks: Locks::default(), signed: false, encrypted: false, changed: Vec::new() };
    if format == Format::Ooxml && bytes.starts_with(&CFB_MAGIC) {
        result.encrypted = true;
        return Ok(result);
    }
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(zip_err)?;
        let name = entry.name().map_err(zip_err)?.into_owned();
        match format {
            Format::Ooxml if name.starts_with("_xmlsignatures/") => result.signed = true,
            Format::Odf if name.starts_with("META-INF/") && name.ends_with("signatures.xml") => result.signed = true,
            _ => {}
        }
        let is_manifest = format == Format::Odf && name == "META-INF/manifest.xml";
        let needles = candidate(format, &name);
        if needles.is_none() && !is_manifest {
            continue;
        }
        let mut data = Vec::new();
        (&mut entry).take(MAX_PART + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_PART {
            return Err(UnlockError::Document(format!("{name}: part too large")));
        }
        if is_manifest {
            result.encrypted |= contains(&data, b"encryption-data");
            continue;
        }
        if !needles.unwrap().iter().any(|n| contains(&data, n)) {
            continue;
        }
        let rules = Rules::for_part(format, &name);
        if let Some(new) = rewrite(&data, &rules, &mut result.locks).map_err(|e| xml_err(&name, e))? {
            result.changed.push((i, new));
        }
    }
    Ok(result)
}

/// Ermittelt den Schutzstatus eines Office-Dokuments.
pub fn inspect(path: &Path, format: Format) -> Result<Inspection, UnlockError> {
    let bytes = std::fs::read(path)?;
    let s = scan(&bytes, format)?;
    let protection = if s.encrypted {
        Protection::PasswordRequired
    } else if !s.locks.is_empty() {
        Protection::RestrictionsOnly
    } else {
        Protection::None
    };
    Ok(Inspection { protection, permissions: None, signed: s.signed, locks: s.locks })
}

/// Entfernt Bearbeitungs-, Blatt- und Strukturschutz und schreibt das Ergebnis nach `output`.
pub fn unlock(input: &Path, output: &Path, format: Format) -> Result<Protection, UnlockError> {
    let bytes = std::fs::read(input)?;
    let s = scan(&bytes, format)?;
    if s.encrypted {
        return Err(UnlockError::OfficeEncrypted);
    }
    if s.changed.is_empty() {
        return Err(UnlockError::NotEncrypted);
    }
    let out = repack(&bytes, s.changed)?;
    crate::core::write_atomic(output, &out)?;
    Ok(Protection::RestrictionsOnly)
}

/// Baut das ZIP neu: geänderte Teile werden neu komprimiert, alle anderen roh kopiert
/// (Reihenfolge, Kompression und Zeitstempel bleiben erhalten – bei ODF muss `mimetype`
/// unkomprimiert am Anfang stehen).
fn repack(bytes: &[u8], mut changed: Vec<(usize, Vec<u8>)>) -> Result<Vec<u8>, UnlockError> {
    use zip::write::SimpleFileOptions;
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zip_err)?;
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::with_capacity(bytes.len())));
    for i in 0..zip.len() {
        if let Some(pos) = changed.iter().position(|(idx, _)| *idx == i) {
            let (_, data) = changed.swap_remove(pos);
            let entry = zip.by_index_raw(i).map_err(zip_err)?;
            let mut opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .large_file(data.len() as u64 >= u64::from(u32::MAX));
            if let Some(t) = entry.last_modified() {
                opts = opts.last_modified_time(t);
            }
            let name = entry.name().map_err(zip_err)?.into_owned();
            drop(entry);
            writer.start_file(name, opts).map_err(zip_err)?;
            writer.write_all(&data)?;
        } else {
            writer.raw_copy_file(zip.by_index_raw(i).map_err(zip_err)?).map_err(zip_err)?;
        }
    }
    if !zip.comment().is_empty() {
        writer.set_raw_comment(zip.comment().to_vec().into_boxed_slice()).map_err(zip_err)?;
    }
    Ok(writer.finish().map_err(zip_err)?.into_inner())
}

// ---------- XML-Umschreiben ----------

/// Was in einem bestimmten XML-Teil gesucht wird.
#[derive(Default)]
struct Rules {
    /// OOXML: Elemente (lokaler Name), die komplett entfernt werden, sofern sie wirksam sind.
    ooxml_elements: bool,
    /// ODF content/styles: Schutz-Attribute an Tabellen, Bereichen und der Tabellendokument-Wurzel.
    odf_attributes: bool,
    /// ODF settings.xml: Konfigurationseinträge.
    odf_settings: bool,
}

impl Rules {
    fn for_part(format: Format, name: &str) -> Rules {
        match format {
            Format::Ooxml => Rules { ooxml_elements: true, ..Rules::default() },
            Format::Odf if name == "settings.xml" => Rules { odf_settings: true, ..Rules::default() },
            Format::Odf => Rules { odf_attributes: true, ..Rules::default() },
        }
    }
}

fn attr_value(e: &BytesStart, qname: &[u8]) -> Option<Vec<u8>> {
    e.attributes().flatten().find(|a| a.key.as_ref() == qname).map(|a| a.value.into_owned())
}

/// Attribut nach lokalem Namen (OOXML-Attribute tragen je nach Teil ein Präfix wie `w:`).
fn attr_local(e: &BytesStart, local: &[u8]) -> Option<Vec<u8>> {
    e.attributes().flatten().find(|a| a.key.local_name().as_ref() == local).map(|a| a.value.into_owned())
}

fn is_true(v: Option<Vec<u8>>) -> bool {
    matches!(v.as_deref(), Some(b"1" | b"true" | b"on"))
}

/// OOXML: Liefert die Schutzart, wenn das Element ein wirksamer Schutz-Eintrag ist.
fn ooxml_lock(e: &BytesStart) -> Option<Locks> {
    match e.local_name().as_ref() {
        // Word: nur wirksam, wenn `enforcement` gesetzt ist.
        b"documentProtection" => is_true(attr_local(e, b"enforcement")).then_some(Locks::EDITING),
        // Word: Kennwort zum Ändern / schreibgeschützt empfehlen.
        b"writeProtection" => Some(Locks::READ_ONLY),
        // Excel: Blattschutz nur bei sheet="1".
        b"sheetProtection" => is_true(attr_local(e, b"sheet")).then_some(Locks::SHEETS),
        b"workbookProtection" => (is_true(attr_local(e, b"lockStructure"))
            || is_true(attr_local(e, b"lockWindows"))
            || is_true(attr_local(e, b"lockRevision")))
        .then_some(Locks::STRUCTURE),
        // Excel: Kennwort zum Ändern / schreibgeschützt empfehlen (nur `userName` ist kein Schutz).
        b"fileSharing" => {
            e.attributes().flatten().any(|a| a.key.local_name().as_ref() != b"userName").then_some(Locks::READ_ONLY)
        }
        // PowerPoint: Kennwort zum Ändern.
        b"modifyVerifier" => Some(Locks::READ_ONLY),
        _ => None,
    }
}

/// ODF: Entfernt Schutz-Attribute. Liefert das neue Element, wenn sich etwas geändert hat.
fn odf_strip(e: &BytesStart, locks: &mut Locks) -> Option<BytesStart<'static>> {
    let name = e.name();
    let (flag, lock): (&[u8], Locks) = match name.as_ref() {
        b"table:table" => (b"table:protected", Locks::SHEETS),
        b"office:spreadsheet" => (b"table:structure-protected", Locks::STRUCTURE),
        // Nur echte Bereiche – Verzeichnisse (text:table-of-content …) sind ohne Kennwort geschützt.
        b"text:section" => (b"text:protected", Locks::SECTIONS),
        _ => return None,
    };
    if !is_true(attr_value(e, flag)) {
        return None;
    }
    locks.insert(lock);
    let drop = |a: &Attribute| {
        let k = a.key.as_ref();
        k == flag || a.key.local_name().as_ref().starts_with(b"protection-key")
    };
    Some(rebuild(e, drop))
}

/// Baut ein Start-Element ohne die von `drop` gewählten Attribute neu auf.
fn rebuild(e: &BytesStart, drop: impl Fn(&Attribute) -> bool) -> BytesStart<'static> {
    let mut out = BytesStart::new(String::from_utf8_lossy(e.name().as_ref()).into_owned());
    for a in e.attributes().with_checks(false).flatten() {
        if drop(&a) {
            continue;
        }
        // Wert bleibt roh (bereits maskiert). Ein Wert aus einfachen Anführungszeichen kann ein
        // unmaskiertes `"` enthalten – das muss für doppelte Anführungszeichen maskiert werden.
        let value = if a.value.contains(&b'"') {
            a.value.iter().flat_map(|&b| if b == b'"' { b"&quot;".to_vec() } else { vec![b] }).collect()
        } else {
            a.value.into_owned()
        };
        out.push_attribute(Attribute { key: a.key, value: value.into() });
    }
    out
}

/// ODF settings.xml: neuer Text für einen Konfigurationseintrag (oder `None` = Eintrag entfernen).
fn odf_setting(name: &[u8]) -> Option<(Locks, Option<&'static str>)> {
    match name {
        b"LoadReadonly" => Some((Locks::READ_ONLY, Some("false"))),
        b"RedlineProtectionKey" => Some((Locks::TRACKED_CHANGES, Some(""))),
        b"ModifyPasswordInfo" => Some((Locks::READ_ONLY, None)),
        _ => None,
    }
}

/// Schreibt einen XML-Teil um. Liefert `None`, wenn nichts zu ändern war.
/// Unberührte Ereignisse werden byte-genau übernommen.
/// Fehlerhaftes XML (falsch geschlossene oder offene Elemente) wird abgelehnt, statt es
/// umzuschreiben – sonst entstünde eine kaputte Datei.
fn rewrite(xml: &[u8], rules: &Rules, locks: &mut Locks) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    // Verschachtelungstiefe – muss am Ende wieder 0 sein
    let mut depth = 0usize;
    let mut writer = quick_xml::Writer::new(Vec::with_capacity(xml.len()));
    let mut changed = false;
    // Tiefe innerhalb eines Elements, das komplett entfernt wird.
    let mut skip = 0usize;
    // ODF-Einstellung, deren Textinhalt ersetzt wird: (neuer Text, Text schon gesehen, Sperre)
    let mut replace: Option<(&'static str, bool, Locks)> = None;

    loop {
        let ev = reader.read_event()?;
        match ev {
            Event::Start(_) => depth += 1,
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof if depth > 0 => return Err("unexpected end of document".into()),
            _ => {}
        }
        if skip > 0 {
            match ev {
                Event::Start(_) => skip += 1,
                Event::End(_) => skip -= 1,
                Event::Eof => break,
                _ => {}
            }
            continue;
        }
        match ev {
            Event::Eof => break,
            Event::Start(ref e) | Event::Empty(ref e) => {
                let is_start = matches!(ev, Event::Start(_));
                if rules.ooxml_elements
                    && let Some(lock) = ooxml_lock(e)
                {
                    locks.insert(lock);
                    changed = true;
                    skip = usize::from(is_start);
                    continue;
                }
                if rules.odf_attributes
                    && let Some(new) = odf_strip(e, locks)
                {
                    changed = true;
                    writer.write_event(if is_start { Event::Start(new) } else { Event::Empty(new) })?;
                    continue;
                }
                if rules.odf_settings
                    && let Some(cfg) = attr_value(e, b"config:name")
                    && let Some((lock, new_text)) = odf_setting(&cfg)
                {
                    match new_text {
                        None => {
                            locks.insert(lock);
                            changed = true;
                            skip = usize::from(is_start);
                            continue;
                        }
                        Some(text) if is_start => replace = Some((text, false, lock)),
                        Some(_) => {}
                    }
                }
                writer.write_event(ev)?;
            }
            Event::Text(ref t) if replace.is_some() => {
                let (new, seen, lock) = replace.as_mut().unwrap();
                *seen = true;
                if &t[..] != new.as_bytes() && !(new.is_empty() && t.iter().all(u8::is_ascii_whitespace)) {
                    locks.insert(*lock);
                    changed = true;
                    if !new.is_empty() {
                        writer.write_event(Event::Text(BytesText::from_escaped(*new)))?;
                    }
                } else {
                    writer.write_event(ev)?;
                }
            }
            Event::End(_) => {
                replace = None;
                writer.write_event(ev)?;
            }
            _ => writer.write_event(ev)?,
        }
    }
    Ok(changed.then(|| writer.into_inner()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;

    /// Baut ein ZIP aus (Name, Inhalt, komprimiert?).
    pub(crate) fn make_zip(path: &Path, parts: &[(&str, &str, bool)]) {
        let mut w = zip::ZipWriter::new(std::fs::File::create(path).unwrap());
        for (name, data, deflate) in parts {
            let method = if *deflate { zip::CompressionMethod::Deflated } else { zip::CompressionMethod::Stored };
            w.start_file(*name, SimpleFileOptions::default().compression_method(method)).unwrap();
            w.write_all(data.as_bytes()).unwrap();
        }
        w.finish().unwrap();
    }

    fn read_part(path: &Path, name: &str) -> String {
        let mut z = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
        let mut s = String::new();
        z.by_name(name).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    const CT: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#;

    pub(crate) const WORD_SETTINGS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:writeProtection w:recommended="1"/><w:zoom w:percent="100"/><w:documentProtection w:edit="readOnly" w:enforcement="1" w:cryptProviderType="rsaAES" w:hash="abc=" w:salt="def="/><w:defaultTabStop w:val="708"/><!-- Kommentar &amp; Co --></w:settings>"#;

    pub(crate) fn docx(dir: &Path, name: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        make_zip(
            &p,
            &[
                ("[Content_Types].xml", CT, true),
                (
                    "word/document.xml",
                    "<w:document xmlns:w=\"x\"><w:body><w:p><w:r><w:t>Geheimer Text &amp; mehr</w:t></w:r></w:p></w:body></w:document>",
                    true,
                ),
                ("word/settings.xml", WORD_SETTINGS, true),
            ],
        );
        p
    }

    #[test]
    fn word_bearbeitungsschutz() {
        let dir = crate::core::tests::tmpdir("docx");
        let p = docx(&dir, "brief.docx");
        let i = inspect(&p, Format::Ooxml).unwrap();
        assert_eq!(i.protection, Protection::RestrictionsOnly);
        assert_eq!(i.locks, {
            let mut l = Locks::EDITING;
            l.insert(Locks::READ_ONLY);
            l
        });
        let out = dir.join("out.docx");
        assert_eq!(unlock(&p, &out, Format::Ooxml).unwrap(), Protection::RestrictionsOnly);
        let s = read_part(&out, "word/settings.xml");
        assert_eq!(
            s,
            WORD_SETTINGS
                .replace(r#"<w:writeProtection w:recommended="1"/>"#, "")
                .replace(r#"<w:documentProtection w:edit="readOnly" w:enforcement="1" w:cryptProviderType="rsaAES" w:hash="abc=" w:salt="def="/>"#, "")
        );
        // unveränderter Teil bleibt byte-genau gleich
        assert!(read_part(&out, "word/document.xml").contains("Geheimer Text &amp; mehr"));
        assert_eq!(inspect(&out, Format::Ooxml).unwrap().protection, Protection::None);
        assert!(matches!(unlock(&out, &dir.join("x.docx"), Format::Ooxml), Err(UnlockError::NotEncrypted)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn word_ohne_erzwungenen_schutz() {
        let dir = crate::core::tests::tmpdir("docx-off");
        let p = dir.join("frei.docx");
        let settings =
            r#"<w:settings xmlns:w="x"><w:documentProtection w:edit="readOnly" w:enforcement="0"/></w:settings>"#;
        make_zip(&p, &[("[Content_Types].xml", CT, true), ("word/settings.xml", settings, true)]);
        assert_eq!(inspect(&p, Format::Ooxml).unwrap().protection, Protection::None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn excel_blatt_und_mappe() {
        let dir = crate::core::tests::tmpdir("xlsx");
        let p = dir.join("tabelle.xlsx");
        let wb = r#"<workbook xmlns="x"><fileSharing userName="A"/><workbookProtection workbookAlgorithmName="SHA-512" lockStructure="1"/><sheets><sheet name="Eins" sheetId="1"/></sheets></workbook>"#;
        let sheet1 = r#"<worksheet xmlns="x"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>sheetProtection als Text</t></is></c></row></sheetData><sheetProtection algorithmName="SHA-512" sheet="1" objects="1"/><protectedRanges><protectedRange sqref="A1" name="r"/></protectedRanges></worksheet>"#;
        let sheet2 = r#"<worksheet xmlns="x"><sheetData/><sheetProtection sheet="0"/></worksheet>"#;
        make_zip(
            &p,
            &[
                ("[Content_Types].xml", CT, true),
                ("xl/workbook.xml", wb, true),
                ("xl/worksheets/sheet1.xml", sheet1, true),
                ("xl/worksheets/sheet2.xml", sheet2, false),
            ],
        );
        let i = inspect(&p, Format::Ooxml).unwrap();
        assert_eq!(i.locks, {
            let mut l = Locks::STRUCTURE;
            l.insert(Locks::SHEETS);
            l
        });
        let out = dir.join("out.xlsx");
        unlock(&p, &out, Format::Ooxml).unwrap();
        let wb2 = read_part(&out, "xl/workbook.xml");
        assert!(wb2.contains(r#"<fileSharing userName="A"/>"#) && !wb2.contains("workbookProtection"));
        let s1 = read_part(&out, "xl/worksheets/sheet1.xml");
        assert!(!s1.contains("<sheetProtection") && s1.contains("sheetProtection als Text"));
        // nicht wirksamer Schutz bleibt unangetastet
        assert_eq!(read_part(&out, "xl/worksheets/sheet2.xml"), sheet2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn powerpoint_kennwort_zum_aendern() {
        let dir = crate::core::tests::tmpdir("pptx");
        let p = dir.join("folien.pptx");
        let pres = r#"<p:presentation xmlns:p="x"><p:sldIdLst/><p:modifyVerifier p:cryptProviderType="rsaAES" p:hashData="x"/></p:presentation>"#;
        make_zip(&p, &[("[Content_Types].xml", CT, true), ("ppt/presentation.xml", pres, true)]);
        assert_eq!(inspect(&p, Format::Ooxml).unwrap().locks, Locks::READ_ONLY);
        let out = dir.join("out.pptx");
        unlock(&p, &out, Format::Ooxml).unwrap();
        assert_eq!(
            read_part(&out, "ppt/presentation.xml"),
            r#"<p:presentation xmlns:p="x"><p:sldIdLst/></p:presentation>"#
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn verschluesselt_und_signiert() {
        let dir = crate::core::tests::tmpdir("ooxml-enc");
        let p = dir.join("geheim.docx");
        let mut data = CFB_MAGIC.to_vec();
        data.extend_from_slice(&[0u8; 512]);
        std::fs::write(&p, data).unwrap();
        assert_eq!(inspect(&p, Format::Ooxml).unwrap().protection, Protection::PasswordRequired);
        assert!(matches!(unlock(&p, &dir.join("x.docx"), Format::Ooxml), Err(UnlockError::OfficeEncrypted)));

        let s = dir.join("signiert.docx");
        make_zip(
            &s,
            &[
                ("[Content_Types].xml", CT, true),
                ("word/settings.xml", WORD_SETTINGS, true),
                ("_xmlsignatures/sig1.xml", "<s/>", true),
            ],
        );
        assert!(inspect(&s, Format::Ooxml).unwrap().signed);
        assert!(!inspect(&docx(&dir, "plain.docx"), Format::Ooxml).unwrap().signed);
        std::fs::remove_dir_all(dir).ok();
    }

    const ODS_CONTENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="o" xmlns:table="t" xmlns:text="x"><office:body><office:spreadsheet table:structure-protected="true" table:protection-key="AAA=" table:protection-key-digest-algorithm="http://www.w3.org/2000/09/xmldsig#sha256"><table:table table:name="Blatt1" table:style-name='ta"1' table:protected="true" table:protection-key="BBB=" table:protection-key-digest-algorithm="sha256"><table:table-protection table:select-unprotected-cells="true"/><table:table-row><table:table-cell><text:p>Wert &lt; 5</text:p></table:table-cell></table:table-row></table:table><table:table table:name="Blatt2"/></office:spreadsheet></office:body></office:document-content>"#;

    fn ods(dir: &Path, name: &str, settings: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        make_zip(
            &p,
            &[
                ("mimetype", "application/vnd.oasis.opendocument.spreadsheet", false),
                ("content.xml", ODS_CONTENT, true),
                ("settings.xml", settings, true),
                ("META-INF/manifest.xml", "<manifest:manifest xmlns:manifest=\"m\"/>", true),
            ],
        );
        p
    }

    #[test]
    fn odf_tabelle() {
        let dir = crate::core::tests::tmpdir("ods");
        let settings = r#"<office:document-settings xmlns:office="o" xmlns:config="c"><config:config-item config:name="LoadReadonly" config:type="boolean">true</config:config-item><config:config-item config:name="Other" config:type="boolean">true</config:config-item></office:document-settings>"#;
        let p = ods(&dir, "tabelle.ods", settings);
        let i = inspect(&p, Format::Odf).unwrap();
        assert_eq!(i.protection, Protection::RestrictionsOnly);
        let mut want = Locks::STRUCTURE;
        want.insert(Locks::SHEETS);
        want.insert(Locks::READ_ONLY);
        assert_eq!(i.locks, want);

        let out = dir.join("out.ods");
        unlock(&p, &out, Format::Odf).unwrap();
        let c = read_part(&out, "content.xml");
        assert!(c.contains(r#"<office:spreadsheet>"#), "{c}");
        assert!(c.contains(r#"<table:table table:name="Blatt1" table:style-name="ta&quot;1">"#), "{c}");
        assert!(c.contains("<table:table-protection") && c.contains("Wert &lt; 5"));
        assert!(!c.contains("protection-key") && !c.contains("protected=\"true\""));
        let s = read_part(&out, "settings.xml");
        assert!(s.contains(r#"config:name="LoadReadonly" config:type="boolean">false<"#));
        assert!(s.contains(r#"config:name="Other" config:type="boolean">true<"#));

        // mimetype muss erster, unkomprimierter Eintrag bleiben
        let mut z = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
        let first = z.by_index(0).unwrap();
        assert_eq!(first.name().unwrap(), "mimetype");
        assert_eq!(first.compression(), zip::CompressionMethod::Stored);
        drop(first);
        assert_eq!(inspect(&out, Format::Odf).unwrap().protection, Protection::None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn odf_text_bereiche_und_aenderungen() {
        let dir = crate::core::tests::tmpdir("odt");
        let p = dir.join("text.odt");
        let content = r#"<office:document-content xmlns:office="o" xmlns:text="x"><office:body><office:text><text:table-of-content text:protected="true" text:name="Inhalt"/><text:section text:name="B1" text:protected="true" text:protection-key="CCC="><text:p>Gesperrt</text:p></text:section></office:text></office:body></office:document-content>"#;
        let settings = r#"<office:document-settings xmlns:config="c"><config:config-item config:name="RedlineProtectionKey" config:type="base64Binary">ZZZ=</config:config-item><config:config-item-map-indexed config:name="ModifyPasswordInfo"><config:config-item-map-entry><config:config-item config:name="x">1</config:config-item></config:config-item-map-entry></config:config-item-map-indexed></office:document-settings>"#;
        make_zip(
            &p,
            &[
                ("mimetype", "application/vnd.oasis.opendocument.text", false),
                ("content.xml", content, true),
                ("settings.xml", settings, true),
            ],
        );
        let i = inspect(&p, Format::Odf).unwrap();
        let mut want = Locks::SECTIONS;
        want.insert(Locks::TRACKED_CHANGES);
        want.insert(Locks::READ_ONLY);
        assert_eq!(i.locks, want);
        let out = dir.join("out.odt");
        unlock(&p, &out, Format::Odf).unwrap();
        let c = read_part(&out, "content.xml");
        assert!(
            c.contains(r#"<text:section text:name="B1">"#)
                && c.contains(r#"text:table-of-content text:protected="true""#)
        );
        let s = read_part(&out, "settings.xml");
        assert_eq!(
            s,
            r#"<office:document-settings xmlns:config="c"><config:config-item config:name="RedlineProtectionKey" config:type="base64Binary"></config:config-item></office:document-settings>"#
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn odf_verschluesselt() {
        let dir = crate::core::tests::tmpdir("odf-enc");
        let p = dir.join("geheim.odt");
        make_zip(
            &p,
            &[
                ("mimetype", "application/vnd.oasis.opendocument.text", false),
                ("content.xml", "binär", false),
                (
                    "META-INF/manifest.xml",
                    "<manifest:manifest xmlns:manifest=\"m\"><manifest:file-entry><manifest:encryption-data/></manifest:file-entry></manifest:manifest>",
                    true,
                ),
            ],
        );
        assert_eq!(inspect(&p, Format::Odf).unwrap().protection, Protection::PasswordRequired);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn kategorien_decken_alle_endungen_ab() {
        let mut a: Vec<&str> = CATEGORIES.iter().flat_map(|(_, e)| e.iter().copied()).collect();
        let mut b: Vec<&str> = extensions().collect();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b);
    }

    /// Kaputte Dateien: verständlicher Fehler, kein Absturz, keine (halbe) Ausgabedatei.
    #[test]
    fn kaputte_dateien() {
        let dir = crate::core::tests::tmpdir("office-broken");
        let out = dir.join("out.docx");
        let check = |p: &Path, format: Format| {
            assert!(inspect(p, format).is_err(), "{p:?}: inspect muss scheitern");
            assert!(unlock(p, &out, format).is_err(), "{p:?}: unlock muss scheitern");
            assert!(!out.exists(), "{p:?}: es darf keine Ausgabe entstehen");
        };

        // gar kein ZIP
        let p = dir.join("text.docx");
        std::fs::write(&p, "Das ist nur Text.").unwrap();
        check(&p, Format::Ooxml);

        // leere Datei
        let p = dir.join("leer.xlsx");
        std::fs::write(&p, "").unwrap();
        check(&p, Format::Ooxml);

        // abgeschnittenes ZIP
        let full = docx(&dir, "ganz.docx");
        let bytes = std::fs::read(&full).unwrap();
        let p = dir.join("abgeschnitten.docx");
        std::fs::write(&p, &bytes[..bytes.len() / 2]).unwrap();
        check(&p, Format::Ooxml);

        // fehlerhaftes XML im Schutz-Teil
        let p = dir.join("kaputt.docx");
        make_zip(
            &p,
            &[
                ("[Content_Types].xml", CT, true),
                ("word/settings.xml", "<w:settings><w:documentProtection w:enforcement=\"1\"/></w:falsch>", true),
            ],
        );
        let e = unlock(&p, &out, Format::Ooxml).unwrap_err();
        assert!(matches!(e, UnlockError::Document(ref m) if m.contains("word/settings.xml")), "{e}");
        assert!(!out.exists());

        // ODF mit kaputtem content.xml
        let p = dir.join("kaputt.ods");
        make_zip(
            &p,
            &[
                ("mimetype", "application/vnd.oasis.opendocument.spreadsheet", false),
                ("content.xml", "<office:document-content><table:table table:protected=\"true\"", true),
            ],
        );
        check(&p, Format::Odf);

        // Original bleibt bei Fehler unangetastet, auch beim Überschreiben an Ort und Stelle
        let p = dir.join("inplace.docx");
        std::fs::write(&p, "kein zip").unwrap();
        assert!(unlock(&p, &p, Format::Ooxml).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), b"kein zip");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn endungen() {
        assert_eq!(format_of(Path::new("a.DOCX")), Some(Format::Ooxml));
        assert_eq!(format_of(Path::new("a.ods")), Some(Format::Odf));
        assert_eq!(format_of(Path::new("a.pdf")), None);
        assert_eq!(format_of(Path::new("a.doc")), None);
    }
}
