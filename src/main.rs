// Unter Windows im Release-Build kein Konsolenfenster für die GUI öffnen.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod core;
mod gui;
mod i18n;
mod reveal;
mod settings;

use std::path::PathBuf;
use std::process::ExitCode;

const HELP: &str = "\
Doclatch – removes or adds password protection and restrictions for PDF files.

Usage:
  doclatch                           Start the graphical interface
  doclatch --gui FILE...             Open the interface with these files
  doclatch [OPTIONS] FILE...         Unlock (default) on the command line
  doclatch --protect [OPTIONS] FILE...  Protect with AES-256

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
      --owner-password PW   Password for full permissions (optional; empty = random)
      --allow LIST          Allowed actions, comma-separated (default: none):
                            print, print-hq, modify, copy, annotate, forms,
                            accessibility, assemble, all, none

This software is provided \"as is\", without warranty of any kind. Use it at your
own risk and keep backups of important files. Only process documents you are
entitled to edit.
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

    if protect && !opts.is_effective() {
        eprintln!("Nothing to protect: set --open-password or restrict at least one permission (--allow).");
        return ExitCode::FAILURE;
    }
    let default_target = |input: &PathBuf, dir: Option<&std::path::Path>| {
        if protect { core::protected_output(input, dir) } else { core::default_output(input, dir) }
    };

    let mut failed = 0;
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
        let result = if protect {
            core::protect(input, &target, &opts, password.as_deref()).map(|()| "protected".to_string())
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
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// `--info`: Schutzstatus und Berechtigungen anzeigen (englisch, wie die gesamte CLI).
fn print_info(files: &[PathBuf]) -> ExitCode {
    let mut failed = 0;
    for f in files {
        match core::inspect(f) {
            Ok(i) => {
                println!("{}: {}", f.display(), i.protection);
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
