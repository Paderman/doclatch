# Changelog

All notable changes to Doclatch are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); version numbers follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] – unreleased

### Added

- **Office documents:** editing, sheet and structure protection is removed from Word, Excel and
  PowerPoint files (`.docx`, `.xlsx`, `.pptx` including macro and template variants) and from
  OpenDocument files (`.odt`, `.ods`, `.odp`, `.odg` and templates). Covered: editing restrictions,
  sheet and workbook structure protection, protected sections, protected change tracking,
  “password to modify” and the read-only recommendation. Only effective protection entries are
  removed; all other parts of the file stay byte-for-byte unchanged.
- **Decrypting Office documents** with a known password: Word, Excel and PowerPoint with Standard
  (AES) or Agile encryption, OpenDocument with AES-256-GCM/Argon2id (LibreOffice 24.2 and later) or
  AES-256-CBC/PBKDF2. Remaining editing protection is removed in the same step. The password field
  appears for encrypted Office files as it does for PDF files.
- Digital signatures in Office files are detected.
- `--info` lists the protection types found in Office documents.
- **Password generator** next to the open and permissions password (22 random characters without
  easily confused ones such as `0/O` or `l/1/I`), plus a button to copy a password.
- **Password list export** after protecting: result files with their passwords as readable text
  (`.txt`) or as CSV for importing into password managers (`.csv`). On Linux and macOS the file is
  readable only by the owner. A random permissions password is never stored.
- “×” inside password fields to clear them.
- Details on hover (or long press on touch screens) over a whole file entry: permissions or
  Office protection before processing, applied protection or removed restrictions afterwards,
  full error messages.
- File dialog filters: all supported files, PDF, Office files, text documents, spreadsheets,
  presentations and drawings, each with its extensions.

### Changed

- In wide windows, “Overwrite original” and “Save to” move next to the main button.
- Slimmer drop area, options panel and action bar; the drop area lists the common extensions.
- Long titles shrink to fit small windows instead of overflowing.
- Texts in all languages no longer address the reader directly.
- Smaller debug builds (line tables only, no debug info for dependencies).

### Fixed

- Malformed XML in Office documents is rejected with an error instead of producing a broken file.

## [0.1.0] – 2026-11-18

First release: removes and adds password protection and permission restrictions for PDF files
(RC4 40/128-bit, AES-128, AES-256), graphical interface in 11 languages and command line,
optional update check.

[0.2.0]: https://github.com/Paderman/doclatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Paderman/doclatch/releases/tag/v0.1.0
