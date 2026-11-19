// Unter Windows im Release-Build kein Konsolenfenster für die GUI öffnen.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod core;
mod desktop;
mod export;
mod gui;
mod i18n;
mod office;
mod office_crypto;
mod settings;
mod update;

use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
Doclatch – removes or adds password protection and restrictions for PDF files
and decrypts Office documents with a known password or removes their editing,
sheet and structure protection (DOCX, XLSX, PPTX, ODT, ODS, ODP and their templates).

Usage:
  doclatch                           Start the graphical interface
  doclatch --gui FILE...             Open the interface with these files
  doclatch [OPTIONS] FILE...         Unlock (default) on the command line
  doclatch --protect [OPTIONS] FILE...  Protect with AES-256 (PDF only)

Options:
  -p, --password PW   Current password to open the file (if required)
                      (alternatively via the environment variable DOCLATCH_PASSWORD)
  -o, --output PATH   Output file (single input only) or output folder
      --in-place      Overwrite the original file
  -i, --info          Only show protection status and permissions, change nothing
  -h, --help          Show this help
  -V, --version       Show version and license

Protect options:
      --protect             Encrypt instead of unlocking (output: NAME_protected.pdf)
      --open-password PW    Password required to open the file (optional;
                            alternatively via DOCLATCH_OPEN_PASSWORD)
      --generate-open-password
                            Generate a separate random open password (22 characters)
                            for each file and print it
      --owner-password PW   Password for full permissions (optional; empty = random)
      --allow LIST          Allowed actions, comma-separated (default: none):
                            print, print-hq, modify, copy, annotate, forms,
                            accessibility, assemble, all, none
      --save-passwords FILE Save the result files with their passwords as text,
                            or as CSV for password managers if FILE ends in .csv
                            (readable only by the owner on Linux and macOS;
                            a random permissions password is never stored)

This software is provided \"as is\", without warranty of any kind. Use is at
one's own risk; backups of important files are recommended. Only documents one
is entitled to edit should be processed.
";

/// Namen für `--allow` und `--info`.
const PERM_NAMES: [(core::Permissions, &str, &str); 8] = {
    use core::Permissions as P;
    [
        (P::PRINTABLE, "print", "printing"),
        (P::PRINTABLE_IN_HIGH_QUALITY, "print-hq", "high-quality printing"),
        (P::MODIFIABLE, "modify", "modifying"),
        (P::COPYABLE, "copy", "copying text and images"),
        (P::ANNOTABLE, "annotate", "adding comments"),
        (P::FILLABLE, "forms", "filling in forms"),
        (P::COPYABLE_FOR_ACCESSIBILITY, "accessibility", "extraction for accessibility"),
        (P::ASSEMBLABLE, "assemble", "assembling pages"),
    ]
};

fn parse_allow(list: &str) -> Result<core::Permissions, String> {
    let mut p = core::Permissions::empty();
    for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        match item {
            "all" => p = core::ALL_PERMISSIONS,
            "none" => p = core::Permissions::empty(),
            _ => match PERM_NAMES.iter().find(|(_, n, _)| *n == item) {
                Some((flag, _, _)) => p |= *flag,
                None => return Err(format!("unknown permission for --allow: {item}")),
            },
        }
    }
    Ok(p)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--gui" {
        let files = args.iter().skip(1).map(PathBuf::from).collect();
        return match gui::run(files) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                let t = settings::Settings::load().effective_lang().strings();
                let msg = i18n::fill(t.gui_error, "e", e);
                eprintln!("{msg}");
                // GUI-Programme haben unter Windows keine Konsole – Fehler daher auch als Dialog zeigen.
                rfd::MessageDialog::new()
                    .set_level(rfd::MessageLevel::Error)
                    .set_title("Doclatch")
                    .set_description(msg)
                    .set_buttons(rfd::MessageButtons::Ok)
                    .show();
                ExitCode::FAILURE
            }
        };
    }
    cli(args)
}

/// Windows-Release-Builds haben kein eigenes Konsolenfenster (GUI-Subsystem).
/// Für die CLI hängen wir uns an die Konsole des Aufrufers an, damit Ausgaben sichtbar sind.
#[cfg(windows)]
fn attach_parent_console() {
    use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    // SAFETY: einfacher Win32-Aufruf ohne Zeiger; Fehlschlag (keine Elternkonsole) ist harmlos.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

fn cli(args: Vec<String>) -> ExitCode {
    #[cfg(windows)]
    attach_parent_console();
    let mut password: Option<String> = std::env::var("DOCLATCH_PASSWORD").ok();
    let mut output: Option<PathBuf> = None;
    let mut in_place = false;
    let mut info = false;
    let mut protect = false;
    let mut opts = core::ProtectOptions {
        open_password: std::env::var("DOCLATCH_OPEN_PASSWORD").unwrap_or_default(),
        owner_password: String::new(),
        permissions: core::Permissions::empty(),
    };
    let mut generate = false;
    let mut save_passwords: Option<PathBuf> = None;
    let mut files = Vec::new();

    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("doclatch {} (license: {})", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_LICENSE"));
                return ExitCode::SUCCESS;
            }
            "-p" | "--password" => password = it.next(),
            "-o" | "--output" => output = it.next().map(PathBuf::from),
            "--in-place" => in_place = true,
            "-i" | "--info" => info = true,
            "--protect" => protect = true,
            "--open-password" => opts.open_password = it.next().unwrap_or_default(),
            "--owner-password" => opts.owner_password = it.next().unwrap_or_default(),
            "--generate-open-password" => generate = true,
            "--save-passwords" => save_passwords = it.next().map(PathBuf::from),
            "--allow" => match parse_allow(&it.next().unwrap_or_default()) {
                Ok(p) => opts.permissions = p,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::FAILURE;
                }
            },
            _ => files.push(PathBuf::from(a)),
        }
    }
    if files.is_empty() {
        eprint!("{HELP}");
        return ExitCode::FAILURE;
    }

    if info {
        return print_info(&files);
    }

    if (generate || save_passwords.is_some()) && !protect {
        eprintln!("--generate-open-password and --save-passwords require --protect.");
        return ExitCode::FAILURE;
    }
    if generate && !opts.open_password.is_empty() {
        eprintln!("--generate-open-password cannot be combined with --open-password.");
        return ExitCode::FAILURE;
    }
    if protect && !generate && !opts.is_effective() {
        eprintln!("Nothing to protect: set --open-password or restrict at least one permission (--allow).");
        return ExitCode::FAILURE;
    }
    let default_target = |input: &PathBuf, dir: Option<&std::path::Path>| {
        if protect { core::protected_output(input, dir) } else { core::default_output(input, dir) }
    };

    let mut failed = 0;
    let mut records = Vec::new();
    for input in &files {
        let target = if in_place {
            input.clone()
        } else {
            match &output {
                Some(o) if o.is_dir() => default_target(input, Some(o)),
                Some(o) if files.len() == 1 => o.clone(),
                Some(o) => {
                    eprintln!("-o must be a folder when several files are given: {}", o.display());
                    return ExitCode::FAILURE;
                }
                None => default_target(input, None),
            }
        };
        if core::inspect(input).is_ok_and(|i| i.signed) {
            eprintln!("! {}: digitally signed – the signature will no longer be valid", input.display());
        }
        let result = if protect {
            let mut file_opts = opts.clone();
            if generate {
                match export::generate_password() {
                    Ok(pw) => file_opts.open_password = pw,
                    Err(e) => {
                        eprintln!("✘ random number generator: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            core::protect(input, &target, &file_opts, password.as_deref()).map(|()| {
                records.push(export::Record {
                    file: std::path::absolute(&target).unwrap_or_else(|_| target.clone()),
                    open: file_opts.open_password.clone(),
                    owner: (!file_opts.owner_password.is_empty()).then(|| file_opts.owner_password.clone()),
                });
                if generate {
                    format!("protected, open password: {}", file_opts.open_password)
                } else {
                    "protected".into()
                }
            })
        } else {
            core::unlock(input, &target, password.as_deref()).map(|p| format!("unlocked, was: {p}"))
        };
        match result {
            Ok(what) => println!("✔ {} ({what}) → {}", input.display(), target.display()),
            Err(e) => {
                failed += 1;
                eprintln!("✘ {}: {e}", input.display());
            }
        }
    }
    if let Some(path) = save_passwords {
        if records.iter().any(export::Record::has_password) {
            match export::write(&path, &export::render(&records, &i18n::EN, &path)) {
                Ok(()) => println!("✔ passwords saved → {}", path.display()),
                Err(e) => {
                    failed += 1;
                    eprintln!("✘ {}: {e}", path.display());
                }
            }
        } else {
            println!("No passwords to save (no open or permissions password was set).");
        }
    }
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `--info`: Schutzstatus und Berechtigungen anzeigen (englisch, wie die gesamte CLI).
fn print_info(files: &[PathBuf]) -> ExitCode {
    let mut failed = 0;
    for f in files {
        match core::inspect(f) {
            Ok(i) => {
                println!("{}: {}", f.display(), i.protection);
                if i.signed {
                    println!("  ! digitally signed – the signature becomes invalid when the file is changed");
                }
                if !i.locks.is_empty() {
                    println!("  protection found: {}", i.locks);
                }
                if let Some(perms) = i.permissions {
                    for (flag, _, name) in PERM_NAMES {
                        println!("  {} {name}", if perms.contains(flag) { "✔ allowed:    " } else { "✘ not allowed:" });
                    }
                }
            }
            Err(e) => {
                failed += 1;
                eprintln!("✘ {}: {e}", f.display());
            }
        }
    }
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
