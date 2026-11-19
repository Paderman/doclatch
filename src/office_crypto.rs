//! Entschlüsseln passwortgeschützter Office-Dokumente – nur mit bekanntem Passwort.
//!
//! - OOXML (MS-OFFCRYPTO): „Standard Encryption“ (Office 2007, LibreOffice) und
//!   „Agile Encryption“ (Office 2010 und neuer) in einem OLE-/CFB-Container.
//! - ODF: Gesamtverschlüsselung (`encrypted-package`, LibreOffice ab 24.2: AES-256-GCM + Argon2id)
//!   und klassische Einzeldatei-Verschlüsselung (AES-256-CBC + PBKDF2).
//!
//! Ergebnis ist jeweils das unverschlüsselte ZIP-Paket.

use crate::core::UnlockError;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use base64ct::{Base64, Encoding};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::io::{Cursor, Read, Write};

/// Obergrenze für entschlüsselte bzw. entpackte Daten (Schutz vor manipulierten Größenangaben).
const MAX_PLAIN: u64 = 2 * 1024 * 1024 * 1024;
/// Obergrenze für Runden der Schlüsselableitung (MS-OFFCRYPTO erlaubt höchstens 10 Mio.).
const MAX_ROUNDS: u32 = 10_000_000;
/// Obergrenzen für Argon2 aus dem Manifest: Speicher (KiB), Iterationen, Lanes.
const MAX_ARGON: (u32, u32, u32) = (1024 * 1024, 10, 16);

fn bad(msg: impl Into<String>) -> UnlockError {
    UnlockError::Document(msg.into())
}

// ---------- AES ----------

/// AES mit 128, 192 oder 256 Bit (Agile erlaubt alle drei).
enum Aes {
    A128(aes::Aes128),
    A192(aes::Aes192),
    A256(aes::Aes256),
}

impl Aes {
    fn new(key: &[u8]) -> Result<Aes, UnlockError> {
        Ok(match key.len() {
            16 => Aes::A128(aes::Aes128::new_from_slice(key).unwrap()),
            24 => Aes::A192(aes::Aes192::new_from_slice(key).unwrap()),
            32 => Aes::A256(aes::Aes256::new_from_slice(key).unwrap()),
            n => return Err(bad(format!("unsupported AES key length {n}"))),
        })
    }

    fn decrypt_block(&self, b: &mut [u8]) {
        let b: &mut aes::Block = b.try_into().expect("16-byte block");
        match self {
            Aes::A128(c) => c.decrypt_block(b),
            Aes::A192(c) => c.decrypt_block(b),
            Aes::A256(c) => c.decrypt_block(b),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn encrypt_block(&self, b: &mut [u8]) {
        let b: &mut aes::Block = b.try_into().expect("16-byte block");
        match self {
            Aes::A128(c) => c.encrypt_block(b),
            Aes::A192(c) => c.encrypt_block(b),
            Aes::A256(c) => c.encrypt_block(b),
        }
    }

    /// ECB, Länge muss ein Vielfaches von 16 sein.
    fn decrypt_ecb(&self, data: &mut [u8]) -> Result<(), UnlockError> {
        if !data.len().is_multiple_of(16) {
            return Err(bad("encrypted data is not block aligned"));
        }
        data.as_chunks_mut::<16>().0.iter_mut().for_each(|b| self.decrypt_block(b));
        Ok(())
    }

    /// CBC ohne Padding-Behandlung, Länge muss ein Vielfaches von 16 sein.
    fn decrypt_cbc(&self, iv: &[u8], data: &mut [u8]) -> Result<(), UnlockError> {
        if !data.len().is_multiple_of(16) || iv.len() < 16 {
            return Err(bad("encrypted data is not block aligned"));
        }
        let mut prev = [0u8; 16];
        prev.copy_from_slice(&iv[..16]);
        for b in data.as_chunks_mut::<16>().0 {
            let mut cur = [0u8; 16];
            cur.copy_from_slice(b);
            self.decrypt_block(b);
            b.iter_mut().zip(prev).for_each(|(x, p)| *x ^= p);
            prev = cur;
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn encrypt_cbc(&self, iv: &[u8], data: &mut [u8]) {
        let mut prev = [0u8; 16];
        prev.copy_from_slice(&iv[..16]);
        for b in data.as_chunks_mut::<16>().0 {
            b.iter_mut().zip(prev).for_each(|(x, p)| *x ^= p);
            self.encrypt_block(b);
            prev.copy_from_slice(b);
        }
    }
}

// ---------- Hashes ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_name(name: &str) -> Result<Hash, UnlockError> {
        Ok(match name.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Hash::Sha1,
            "SHA256" => Hash::Sha256,
            "SHA384" => Hash::Sha384,
            "SHA512" => Hash::Sha512,
            _ => return Err(UnlockError::OfficeEncrypted),
        })
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            parts.iter().for_each(|p| d.update(p));
            d.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => run::<Sha1>(parts),
            Hash::Sha256 => run::<Sha256>(parts),
            Hash::Sha384 => run::<Sha384>(parts),
            Hash::Sha512 => run::<Sha512>(parts),
        }
    }
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// H0 = H(salt + Passwort), danach `spin` Runden H(i + H) – gemeinsam für Standard und Agile.
fn spin_hash(hash: Hash, salt: &[u8], password: &str, spin: u32) -> Vec<u8> {
    let mut h = hash.digest(&[salt, &utf16le(password)]);
    for i in 0..spin {
        h = hash.digest(&[&i.to_le_bytes(), &h]);
    }
    h
}

/// Auf `len` Bytes kürzen bzw. mit `fill` auffüllen.
fn fit(mut v: Vec<u8>, len: usize, fill: u8) -> Vec<u8> {
    v.resize(len, fill);
    v
}

// ---------- OOXML ----------

/// Entschlüsselt ein OOXML-Dokument (OLE-Container mit `EncryptionInfo` und `EncryptedPackage`).
pub fn decrypt_ooxml(bytes: &[u8], password: &str) -> Result<Vec<u8>, UnlockError> {
    let mut cfb = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|e| bad(format!("container: {e}")))?;
    let mut read = |name: &str| -> Result<Vec<u8>, UnlockError> {
        let mut s = cfb.open_stream(name).map_err(|_| bad(format!("{name} missing")))?;
        let mut v = Vec::new();
        s.by_ref().take(MAX_PLAIN).read_to_end(&mut v)?;
        Ok(v)
    };
    let info = read("EncryptionInfo")?;
    let package = read("EncryptedPackage")?;
    if info.len() < 8 || package.len() < 8 {
        return Err(bad("encryption info too short"));
    }
    let (major, minor) = (u16::from_le_bytes([info[0], info[1]]), u16::from_le_bytes([info[2], info[3]]));
    let plain = match (major, minor) {
        (4, 4) => agile_decrypt(&info[8..], &package, password)?,
        (2..=4, 2) => standard_decrypt(&info[4..], &package, password)?,
        // 1.1 = RC4 (nur Binärformate), 3.3/4.3 = „Extensible“ – praktisch nicht verbreitet
        _ => return Err(UnlockError::OfficeEncrypted),
    };
    if !plain.starts_with(b"PK") {
        return Err(bad("decrypted data is not a document package"));
    }
    Ok(plain)
}

fn package_size(package: &[u8]) -> Result<usize, UnlockError> {
    let size = u64::from_le_bytes(package[..8].try_into().unwrap());
    if size > (package.len() as u64) || size > MAX_PLAIN {
        return Err(bad("invalid package size"));
    }
    Ok(size as usize)
}

fn u32_at(b: &[u8], pos: usize) -> Result<u32, UnlockError> {
    b.get(pos..pos + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap())).ok_or_else(|| bad("encryption info truncated"))
}

/// Schlüssel nach MS-OFFCRYPTO 2.3.4.7 (Standard Encryption).
fn standard_key(salt: &[u8], password: &str, key_bytes: usize) -> Vec<u8> {
    let h = spin_hash(Hash::Sha1, salt, password, 50_000);
    let h = Hash::Sha1.digest(&[&h, &0u32.to_le_bytes()]);
    let mut b1 = [0x36u8; 64];
    let mut b2 = [0x5cu8; 64];
    for (i, x) in h.iter().enumerate() {
        b1[i] ^= x;
        b2[i] ^= x;
    }
    let mut x = Hash::Sha1.digest(&[&b1]);
    x.extend(Hash::Sha1.digest(&[&b2]));
    x.truncate(key_bytes);
    x
}

/// `data` beginnt nach dem Versionsfeld: Flags, Header-Größe, EncryptionHeader, EncryptionVerifier.
fn standard_decrypt(data: &[u8], package: &[u8], password: &str) -> Result<Vec<u8>, UnlockError> {
    let header_size = u32_at(data, 4)? as usize;
    let header = data.get(8..8 + header_size).ok_or_else(|| bad("encryption header truncated"))?;
    let alg_id = u32_at(header, 8)?;
    let key_bits = u32_at(header, 16)?;
    // 0x660E/0x660F/0x6610 = AES-128/192/256 (RC4 = 0x6801 kommt bei OOXML nicht vor)
    if !matches!(alg_id, 0x660E..=0x6610) {
        return Err(UnlockError::OfficeEncrypted);
    }
    let v = &data[8 + header_size..];
    let salt_size = u32_at(v, 0)? as usize;
    let salt = v.get(4..4 + salt_size).ok_or_else(|| bad("verifier truncated"))?;
    let mut verifier = v.get(4 + salt_size..20 + salt_size).ok_or_else(|| bad("verifier truncated"))?.to_vec();
    let hash_size = u32_at(v, 20 + salt_size)? as usize;
    let mut verifier_hash = v.get(24 + salt_size..56 + salt_size).ok_or_else(|| bad("verifier truncated"))?.to_vec();

    let key = standard_key(salt, password, key_bits as usize / 8);
    let aes = Aes::new(&key)?;
    aes.decrypt_ecb(&mut verifier)?;
    aes.decrypt_ecb(&mut verifier_hash)?;
    if Hash::Sha1.digest(&[&verifier]) != verifier_hash[..hash_size.min(20)] {
        return Err(UnlockError::WrongPassword);
    }
    let size = package_size(package)?;
    let mut body = package[8..].to_vec();
    body.truncate(body.len() / 16 * 16);
    aes.decrypt_ecb(&mut body)?;
    body.truncate(size);
    Ok(body)
}

/// Parameter eines `keyData`- bzw. `encryptedKey`-Elements.
#[derive(Default, Debug)]
struct KeyParams {
    salt: Vec<u8>,
    block_size: usize,
    key_bits: usize,
    hash_size: usize,
    hash: Option<Hash>,
    spin: u32,
    verifier_input: Vec<u8>,
    verifier_value: Vec<u8>,
    key_value: Vec<u8>,
}

fn b64(v: &str) -> Result<Vec<u8>, UnlockError> {
    Base64::decode_vec(v.trim()).map_err(|_| bad("invalid base64 value"))
}

fn read_key_params(e: &BytesStart) -> Result<KeyParams, UnlockError> {
    let mut p = KeyParams::default();
    for a in e.attributes().flatten() {
        let v = a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map_err(|e| bad(e.to_string()))?;
        let num = || v.parse::<usize>().map_err(|_| bad("invalid number in encryption info"));
        match a.key.local_name().as_ref() {
            b"saltValue" => p.salt = b64(&v)?,
            b"blockSize" => p.block_size = num()?,
            b"keyBits" => p.key_bits = num()?,
            b"hashSize" => p.hash_size = num()?,
            b"hashAlgorithm" => p.hash = Some(Hash::from_name(&v)?),
            b"spinCount" => p.spin = num()? as u32,
            b"encryptedVerifierHashInput" => p.verifier_input = b64(&v)?,
            b"encryptedVerifierHashValue" => p.verifier_value = b64(&v)?,
            b"encryptedKeyValue" => p.key_value = b64(&v)?,
            b"cipherAlgorithm" if !v.eq_ignore_ascii_case("AES") => return Err(UnlockError::OfficeEncrypted),
            b"cipherChaining" if v != "ChainingModeCBC" => return Err(UnlockError::OfficeEncrypted),
            _ => {}
        }
    }
    if p.hash.is_none() || ![128, 192, 256].contains(&p.key_bits) || p.block_size != 16 || p.salt.is_empty() {
        return Err(bad("incomplete encryption parameters"));
    }
    Ok(p)
}

const BLOCK_VERIFIER_INPUT: [u8; 8] = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
const BLOCK_VERIFIER_VALUE: [u8; 8] = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];
const BLOCK_KEY_VALUE: [u8; 8] = [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6];

fn agile_params(xml: &[u8]) -> Result<(KeyParams, KeyParams), UnlockError> {
    let mut reader = Reader::from_reader(xml);
    let (mut key_data, mut password_key) = (None, None);
    let mut in_password_encryptor = false;
    loop {
        match reader.read_event().map_err(|e| bad(e.to_string()))? {
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"keyData" => key_data = Some(read_key_params(&e)?),
                b"keyEncryptor" => {
                    in_password_encryptor = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"uri" && a.value.ends_with(b"keyEncryptor/password"));
                }
                b"encryptedKey" if in_password_encryptor => password_key = Some(read_key_params(&e)?),
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    match (key_data, password_key) {
        (Some(k), Some(p)) => Ok((k, p)),
        // nur Zertifikat-Verschlüsselung o. Ä.
        _ => Err(UnlockError::OfficeEncrypted),
    }
}

fn agile_decrypt(xml: &[u8], package: &[u8], password: &str) -> Result<Vec<u8>, UnlockError> {
    let (kd, pk) = agile_params(xml)?;
    let ph = pk.hash.unwrap();
    if pk.spin > MAX_ROUNDS {
        return Err(bad("spin count too high"));
    }
    let h = spin_hash(ph, &pk.salt, password, pk.spin);
    let key_bytes = pk.key_bits / 8;
    let derive = |block: &[u8]| fit(ph.digest(&[&h, block]), key_bytes, 0x36);
    let iv = fit(pk.salt.clone(), pk.block_size, 0x36);
    let decrypt = |block: &[u8], data: &[u8]| -> Result<Vec<u8>, UnlockError> {
        let mut d = data.to_vec();
        Aes::new(&derive(block))?.decrypt_cbc(&iv, &mut d)?;
        Ok(d)
    };
    let verifier = decrypt(&BLOCK_VERIFIER_INPUT, &pk.verifier_input)?;
    let verifier_hash = decrypt(&BLOCK_VERIFIER_VALUE, &pk.verifier_value)?;
    let expected = ph.digest(&[&verifier[..pk.salt.len().min(verifier.len())]]);
    if verifier_hash.get(..pk.hash_size) != expected.get(..pk.hash_size) {
        return Err(UnlockError::WrongPassword);
    }
    let secret = decrypt(&BLOCK_KEY_VALUE, &pk.key_value)?;
    let secret = secret.get(..kd.key_bits / 8).ok_or_else(|| bad("key too short"))?;
    let aes = Aes::new(secret)?;

    // Paket in Segmenten zu 4096 Byte, IV je Segment = H(keyData-Salt + Segmentnummer)
    let size = package_size(package)?;
    let kh = kd.hash.unwrap();
    let mut out = Vec::with_capacity(package.len());
    for (i, seg) in package[8..].chunks(4096).enumerate() {
        let iv = fit(kh.digest(&[&kd.salt, &(i as u32).to_le_bytes()]), kd.block_size, 0x36);
        let mut s = seg[..seg.len() / 16 * 16].to_vec();
        aes.decrypt_cbc(&iv, &mut s)?;
        out.extend_from_slice(&s);
        if out.len() >= size {
            break;
        }
    }
    if out.len() < size {
        return Err(bad("encrypted package truncated"));
    }
    out.truncate(size);
    Ok(out)
}

// ---------- ODF ----------

/// Verschlüsselungsangaben eines Manifest-Eintrags.
#[derive(Default, Debug, Clone)]
struct OdfEntry {
    path: String,
    size: Option<u64>,
    algorithm: String,
    iv: Vec<u8>,
    checksum_type: String,
    checksum: Vec<u8>,
    start_key: String,
    kdf: String,
    salt: Vec<u8>,
    iterations: u32,
    key_size: usize,
    argon: (u32, u32, u32), // Iterationen, Speicher (KiB), Lanes
}

fn attr(e: &BytesStart, local: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == local)
        .and_then(|a| a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()))
}

fn odf_manifest(xml: &[u8]) -> Result<Vec<OdfEntry>, UnlockError> {
    let mut reader = Reader::from_reader(xml);
    let mut entries = Vec::new();
    let mut cur: Option<OdfEntry> = None;
    let num = |v: Option<String>| v.and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    loop {
        match reader.read_event().map_err(|e| bad(format!("manifest: {e}")))? {
            Event::Start(e) | Event::Empty(e) => match e.local_name().as_ref() {
                b"file-entry" => {
                    if let Some(c) = cur.take().filter(|c| !c.algorithm.is_empty()) {
                        entries.push(c);
                    }
                    cur = Some(OdfEntry {
                        path: attr(&e, b"full-path").unwrap_or_default(),
                        size: attr(&e, b"size").and_then(|s| s.parse().ok()),
                        ..OdfEntry::default()
                    });
                }
                b"encryption-data" => {
                    if let Some(c) = cur.as_mut() {
                        c.checksum_type = attr(&e, b"checksum-type").unwrap_or_default();
                        c.checksum = attr(&e, b"checksum").map(|v| b64(&v)).transpose()?.unwrap_or_default();
                    }
                }
                b"algorithm" => {
                    if let Some(c) = cur.as_mut() {
                        c.algorithm = attr(&e, b"algorithm-name").unwrap_or_default();
                        c.iv = attr(&e, b"initialisation-vector").map(|v| b64(&v)).transpose()?.unwrap_or_default();
                    }
                }
                b"start-key-generation" => {
                    if let Some(c) = cur.as_mut() {
                        c.start_key = attr(&e, b"start-key-generation-name").unwrap_or_default();
                    }
                }
                b"key-derivation" => {
                    if let Some(c) = cur.as_mut() {
                        c.kdf = attr(&e, b"key-derivation-name").unwrap_or_default();
                        c.salt = attr(&e, b"salt").map(|v| b64(&v)).transpose()?.unwrap_or_default();
                        c.iterations = num(attr(&e, b"iteration-count"));
                        c.key_size = num(attr(&e, b"key-size")) as usize;
                        c.argon = (
                            num(attr(&e, b"argon2-iterations")),
                            num(attr(&e, b"argon2-memory")),
                            num(attr(&e, b"argon2-lanes")),
                        );
                    }
                }
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    if let Some(c) = cur.filter(|c| !c.algorithm.is_empty()) {
        entries.push(c);
    }
    Ok(entries)
}

/// Entschlüsselt und entpackt einen ODF-Eintrag.
fn odf_decrypt_entry(e: &OdfEntry, data: &[u8], password: &str) -> Result<Vec<u8>, UnlockError> {
    // Startschlüssel: SHA-256 (aktuell) bzw. SHA-1 (sehr alte Dateien) des UTF-8-Passworts
    let start = if e.start_key.is_empty() || e.start_key.ends_with("sha1") || e.start_key == "SHA1" {
        Hash::Sha1.digest(&[password.as_bytes()])
    } else if e.start_key.ends_with("sha256") || e.start_key.ends_with("SHA256") {
        Hash::Sha256.digest(&[password.as_bytes()])
    } else {
        return Err(UnlockError::OfficeEncrypted);
    };
    let key_size = if e.key_size == 0 { 16 } else { e.key_size };
    let mut key = vec![0u8; key_size];
    if e.kdf.ends_with("argon2id") {
        let (t, m, p) = e.argon;
        if m > MAX_ARGON.0 || t > MAX_ARGON.1 || p > MAX_ARGON.2 {
            return Err(bad("key derivation parameters too high"));
        }
        let params = argon2::Params::new(m, t, p, Some(key_size)).map_err(|err| bad(format!("argon2: {err}")))?;
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(&start, &e.salt, &mut key)
            .map_err(|err| bad(format!("argon2: {err}")))?;
    } else if e.kdf.eq_ignore_ascii_case("PBKDF2") || e.kdf.ends_with("#pbkdf2") {
        if e.iterations > MAX_ROUNDS {
            return Err(bad("key derivation parameters too high"));
        }
        pbkdf2::pbkdf2_hmac::<Sha1>(&start, &e.salt, e.iterations.max(1), &mut key);
    } else {
        return Err(UnlockError::OfficeEncrypted);
    }

    let compressed = if e.algorithm.ends_with("aes256-gcm") {
        use aes_gcm::aead::Aead;
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).map_err(|_| bad("invalid key"))?;
        let nonce = aes_gcm::Nonce::try_from(e.iv.as_slice()).map_err(|_| bad("invalid nonce"))?;
        // LibreOffice stellt die Nonce den Daten voran; die Authentifizierung schlägt bei
        // falschem Passwort fehl
        let data = data.strip_prefix(e.iv.as_slice()).unwrap_or(data);
        cipher.decrypt(&nonce, data).map_err(|_| UnlockError::WrongPassword)?
    } else if e.algorithm.ends_with("aes256-cbc") || e.algorithm.ends_with("aes128-cbc") {
        let mut d = data.to_vec();
        Aes::new(&key)?.decrypt_cbc(&e.iv, &mut d).map_err(|_| UnlockError::WrongPassword)?;
        // XML-Encryption-Padding: letztes Byte = Anzahl Füllbytes
        let pad = usize::from(*d.last().ok_or(UnlockError::WrongPassword)?);
        if pad == 0 || pad > 16 || pad > d.len() {
            return Err(UnlockError::WrongPassword);
        }
        d.truncate(d.len() - pad);
        d
    } else {
        // z. B. Blowfish CFB aus OpenOffice 2
        return Err(UnlockError::OfficeEncrypted);
    };

    // Prüfsumme über die ersten 1024 Byte (nur klassische Verschlüsselung)
    if !e.checksum.is_empty() {
        let head = &compressed[..compressed.len().min(1024)];
        let t = e.checksum_type.to_ascii_lowercase();
        let sum = if t.contains("sha256") {
            Hash::Sha256.digest(&[head])
        } else if t.contains("sha1") {
            Hash::Sha1.digest(&[head])
        } else {
            e.checksum.clone()
        };
        if sum != e.checksum {
            return Err(UnlockError::WrongPassword);
        }
    }
    inflate_or_raw(compressed, e.size)
}

/// Verschlüsselte Einträge sind normalerweise vorher mit Deflate gepackt; bereits gepackte
/// Inhalte (z. B. Bilder) können auch ungepackt verschlüsselt sein.
fn inflate_or_raw(data: Vec<u8>, size: Option<u64>) -> Result<Vec<u8>, UnlockError> {
    let limit = size.unwrap_or(MAX_PLAIN).min(MAX_PLAIN);
    let mut out = Vec::new();
    let ok = flate2::read::DeflateDecoder::new(data.as_slice()).take(limit + 1).read_to_end(&mut out).is_ok();
    if ok && size.is_none_or(|s| out.len() as u64 == s) && !out.is_empty() {
        return Ok(out);
    }
    if size.is_none_or(|s| data.len() as u64 == s) {
        return Ok(data);
    }
    Err(UnlockError::WrongPassword)
}

/// Entschlüsselt ein ODF-Paket und liefert das unverschlüsselte Paket.
pub fn decrypt_odf(bytes: &[u8], password: &str) -> Result<Vec<u8>, UnlockError> {
    use zip::write::SimpleFileOptions;
    let zerr = |e: zip::result::ZipError| bad(e.to_string());
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(zerr)?;
    let mut manifest = Vec::new();
    zip.by_name("META-INF/manifest.xml").map_err(zerr)?.take(MAX_PLAIN).read_to_end(&mut manifest)?;
    let entries = odf_manifest(&manifest)?;
    if entries.is_empty() {
        return Err(UnlockError::NotEncrypted);
    }
    let read_raw = |zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str| -> Result<Vec<u8>, UnlockError> {
        let mut v = Vec::new();
        zip.by_name(name).map_err(|_| bad(format!("{name} missing")))?.take(MAX_PLAIN).read_to_end(&mut v)?;
        Ok(v)
    };

    // Gesamtverschlüsselung: das eigentliche Paket steckt verschlüsselt in `encrypted-package`.
    if let Some(e) = entries.iter().find(|e| e.path == "encrypted-package") {
        let data = read_raw(&mut zip, &e.path)?;
        let inner = odf_decrypt_entry(e, &data, password)?;
        if !inner.starts_with(b"PK") {
            return Err(UnlockError::WrongPassword);
        }
        return Ok(inner);
    }

    // Klassisch: jede Datei einzeln. Erst alle entschlüsseln (Passwort prüfen), dann neu packen.
    let mut plain = std::collections::HashMap::new();
    for e in &entries {
        let data = read_raw(&mut zip, &e.path)?;
        plain.insert(e.path.clone(), odf_decrypt_entry(e, &data, password)?);
    }
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::with_capacity(bytes.len())));
    for i in 0..zip.len() {
        let entry = zip.by_index_raw(i).map_err(zerr)?;
        let name = entry.name().map_err(zerr)?.into_owned();
        let time = entry.last_modified();
        let data = if name == "META-INF/manifest.xml" {
            Some(strip_encryption_data(&manifest)?)
        } else {
            plain.remove(&name)
        };
        match data {
            Some(d) => {
                drop(entry);
                let mut o = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
                if let Some(t) = time {
                    o = o.last_modified_time(t);
                }
                w.start_file(name, o).map_err(zerr)?;
                w.write_all(&d)?;
            }
            None => w.raw_copy_file(entry).map_err(zerr)?,
        }
    }
    Ok(w.finish().map_err(zerr)?.into_inner())
}

/// Entfernt `manifest:encryption-data` samt Inhalt aus dem Manifest.
fn strip_encryption_data(xml: &[u8]) -> Result<Vec<u8>, UnlockError> {
    let mut reader = Reader::from_reader(xml);
    let mut writer = quick_xml::Writer::new(Vec::with_capacity(xml.len()));
    let mut skip = 0usize;
    loop {
        let ev = reader.read_event().map_err(|e| bad(format!("manifest: {e}")))?;
        let is_enc = |e: &BytesStart| e.local_name().as_ref() == b"encryption-data";
        match &ev {
            Event::Eof => break,
            _ if skip > 0 => {
                match ev {
                    Event::Start(_) => skip += 1,
                    Event::End(_) => skip -= 1,
                    _ => {}
                }
                continue;
            }
            Event::Start(e) if is_enc(e) => {
                skip = 1;
                continue;
            }
            Event::Empty(e) if is_enc(e) => continue,
            _ => {}
        }
        writer.write_event(ev).map_err(|e| bad(e.to_string()))?;
    }
    Ok(writer.into_inner())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    pub(crate) fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    /// Erzeugt nach MS-OFFCRYPTO eine Agile-verschlüsselte Datei (nur für Tests).
    /// Dass LibreOffice die Ausgabe öffnen kann, wurde geprüft; die Datei liegt als
    /// `agile.docx` in den Testdaten.
    pub(crate) fn agile_encrypt(plain: &[u8], password: &str) -> Vec<u8> {
        let rand = |n: usize| {
            let mut v = vec![0u8; n];
            getrandom::fill(&mut v).unwrap();
            v
        };
        let h = Hash::Sha512;
        let (key_salt, pw_salt, secret, verifier) = (rand(16), rand(16), rand(32), rand(16));
        let spin = 100_000;
        let ph = spin_hash(h, &pw_salt, password, spin);
        let enc = |block: &[u8], data: &[u8]| {
            let mut d = data.to_vec();
            d.resize(d.len().div_ceil(16) * 16, 0);
            Aes::new(&fit(h.digest(&[&ph, block]), 32, 0x36)).unwrap().encrypt_cbc(&pw_salt, &mut d);
            d
        };
        let vin = enc(&BLOCK_VERIFIER_INPUT, &verifier);
        let vval = enc(&BLOCK_VERIFIER_VALUE, &h.digest(&[&verifier]));
        let kval = enc(&BLOCK_KEY_VALUE, &secret);

        let aes = Aes::new(&secret).unwrap();
        let mut package = (plain.len() as u64).to_le_bytes().to_vec();
        for (i, seg) in plain.chunks(4096).enumerate() {
            let iv = fit(h.digest(&[&key_salt, &(i as u32).to_le_bytes()]), 16, 0x36);
            let mut s = seg.to_vec();
            s.resize(s.len().div_ceil(16) * 16, 0);
            aes.encrypt_cbc(&iv, &mut s);
            package.extend(s);
        }
        // HMAC über das Paket (Datenintegrität)
        let hmac_key = rand(64);
        let hmac_val = {
            use hmac::{KeyInit as _, Mac};
            let mut m = hmac::Hmac::<Sha512>::new_from_slice(&hmac_key).unwrap();
            m.update(&package);
            m.finalize().into_bytes().to_vec()
        };
        let enc_secret = |block: [u8; 8], data: &[u8]| {
            let iv = fit(h.digest(&[&key_salt, &block]), 16, 0x36);
            let mut d = data.to_vec();
            aes.encrypt_cbc(&iv, &mut d);
            d
        };
        let ehk = enc_secret([0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6], &hmac_key);
        let ehv = enc_secret([0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33], &hmac_val);
        let b = |v: &[u8]| Base64::encode_string(v);
        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="{}"/><dataIntegrity encryptedHmacKey="{}" encryptedHmacValue="{}"/><keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password"><p:encryptedKey spinCount="{spin}" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="{}" encryptedVerifierHashInput="{}" encryptedVerifierHashValue="{}" encryptedKeyValue="{}"/></keyEncryptor></keyEncryptors></encryption>"#,
            b(&key_salt),
            b(&ehk),
            b(&ehv),
            b(&pw_salt),
            b(&vin),
            b(&vval),
            b(&kval)
        );
        let mut info = vec![4, 0, 4, 0, 0x40, 0, 0, 0];
        info.extend(xml.as_bytes());

        let mut c = cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new())).unwrap();
        c.create_stream("EncryptionInfo").unwrap().write_all(&info).unwrap();
        c.create_stream("EncryptedPackage").unwrap().write_all(&package).unwrap();
        c.flush().unwrap();
        c.into_inner().into_inner()
    }

    fn plain_docx() -> Vec<u8> {
        let dir = crate::core::tests::tmpdir("crypto-plain");
        let p = crate::office::tests::docx(&dir, "x.docx");
        let v = std::fs::read(&p).unwrap();
        std::fs::remove_dir_all(dir).ok();
        v
    }

    /// Erzeugt `agile.docx` neu: `AGILE_OUT=<pfad> cargo test agile_testdatei -- --ignored`
    #[test]
    #[ignore]
    fn agile_testdatei() {
        let plain = decrypt_ooxml(&fixture("standard.docx"), "Geheim-123").unwrap();
        std::fs::write(std::env::var("AGILE_OUT").unwrap(), agile_encrypt(&plain, "Geheim-123")).unwrap();
    }

    #[test]
    fn agile_rundlauf() {
        let plain = plain_docx();
        let enc = agile_encrypt(&plain, "Pässwort");
        assert!(matches!(decrypt_ooxml(&enc, "falsch"), Err(UnlockError::WrongPassword)));
        assert_eq!(decrypt_ooxml(&enc, "Pässwort").unwrap(), plain);
    }

    #[test]
    fn libreoffice_standard() {
        let enc = fixture("standard.docx");
        assert!(matches!(decrypt_ooxml(&enc, "falsch"), Err(UnlockError::WrongPassword)));
        let plain = decrypt_ooxml(&enc, "Geheim-123").unwrap();
        let mut z = zip::ZipArchive::new(Cursor::new(plain)).unwrap();
        let mut doc = String::new();
        z.by_name("word/document.xml").unwrap().read_to_string(&mut doc).unwrap();
        assert!(doc.contains("Geheimer Text äöü"));
    }

    #[test]
    fn agile_aus_testdaten() {
        // von `agile_encrypt` erzeugt und mit LibreOffice gegengeprüft
        let plain = decrypt_ooxml(&fixture("agile.docx"), "Geheim-123").unwrap();
        assert!(plain.starts_with(b"PK"));
    }

    #[test]
    fn odf_gesamtverschluesselung() {
        let enc = fixture("wholesome.odt");
        assert!(matches!(decrypt_odf(&enc, "falsch"), Err(UnlockError::WrongPassword)));
        let plain = decrypt_odf(&enc, "Geheim-123").unwrap();
        let mut z = zip::ZipArchive::new(Cursor::new(plain)).unwrap();
        let mut c = String::new();
        z.by_name("content.xml").unwrap().read_to_string(&mut c).unwrap();
        assert!(c.contains("Geheimer Text äöü"));
    }

    #[test]
    fn odf_klassisch() {
        let enc = fixture("classic.ods");
        assert!(matches!(decrypt_odf(&enc, "falsch"), Err(UnlockError::WrongPassword)));
        let plain = decrypt_odf(&enc, "Geheim-123").unwrap();
        let mut z = zip::ZipArchive::new(Cursor::new(plain)).unwrap();
        let mut c = String::new();
        z.by_name("content.xml").unwrap().read_to_string(&mut c).unwrap();
        assert!(c.contains("Wert 42"));
        let mut m = String::new();
        z.by_name("META-INF/manifest.xml").unwrap().read_to_string(&mut m).unwrap();
        assert!(!m.contains("encryption-data"));
        assert_eq!(z.by_index(0).unwrap().name().unwrap(), "mimetype");
    }

    #[test]
    fn ueberhoehte_parameter() {
        let mut e = OdfEntry {
            algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm".into(),
            start_key: "sha256".into(),
            kdf: "urn:x:argon2id".into(),
            salt: vec![0; 16],
            key_size: 32,
            argon: (3, 64 * 1024 * 1024, 4), // 64 GiB
            ..OdfEntry::default()
        };
        assert!(matches!(odf_decrypt_entry(&e, &[0; 32], "x"), Err(UnlockError::Document(_))));
        e.kdf = "PBKDF2".into();
        e.iterations = u32::MAX;
        assert!(matches!(odf_decrypt_entry(&e, &[0; 32], "x"), Err(UnlockError::Document(_))));
    }

    #[test]
    fn kaputte_container() {
        assert!(decrypt_ooxml(b"nicht ole", "x").is_err());
        let mut enc = fixture("standard.docx");
        enc.truncate(enc.len() / 2);
        assert!(decrypt_ooxml(&enc, "Geheim-123").is_err());
    }
}
