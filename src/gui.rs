//! Moderne, plattformübergreifende Oberfläche mit egui/eframe.

use crate::core::{self, ALL_PERMISSIONS, Permissions, ProtectOptions, Protection, UnlockError};
use crate::i18n::{Lang, Strings, fill};
use crate::settings::{LangPref, Settings, ThemePref, ThemeWatcher};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Sense, Stroke, StrokeKind, Vec2,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

// ---------- Design-Tokens ----------
struct Palette {
    bg: Color32,
    surface: Color32,
    surface_hi: Color32,
    border: Color32,
    text: Color32,
    muted: Color32,
    accent: Color32,
    accent_hi: Color32,
    success: Color32,
    warn: Color32,
    error: Color32,
}

const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x0E, 0x10, 0x16),
    surface: Color32::from_rgb(0x16, 0x19, 0x22),
    surface_hi: Color32::from_rgb(0x1E, 0x22, 0x2E),
    border: Color32::from_rgb(0x2A, 0x2F, 0x3D),
    text: Color32::from_rgb(0xE8, 0xEA, 0xF0),
    muted: Color32::from_rgb(0x8A, 0x90, 0xA2),
    accent: Color32::from_rgb(0x7C, 0x5C, 0xFF),
    accent_hi: Color32::from_rgb(0x95, 0x7B, 0xFF),
    success: Color32::from_rgb(0x3D, 0xD6, 0x8C),
    warn: Color32::from_rgb(0xF5, 0xB8, 0x4B),
    error: Color32::from_rgb(0xFF, 0x5C, 0x7A),
};

const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xF4, 0xF5, 0xF9),
    surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    surface_hi: Color32::from_rgb(0xEC, 0xEE, 0xF4),
    border: Color32::from_rgb(0xDC, 0xDF, 0xE8),
    text: Color32::from_rgb(0x16, 0x18, 0x22),
    muted: Color32::from_rgb(0x6A, 0x70, 0x82),
    accent: Color32::from_rgb(0x63, 0x44, 0xF0),
    accent_hi: Color32::from_rgb(0x75, 0x58, 0xFF),
    success: Color32::from_rgb(0x12, 0x9E, 0x5E),
    warn: Color32::from_rgb(0xB9, 0x7A, 0x08),
    error: Color32::from_rgb(0xD6, 0x2E, 0x4F),
};

// ---------- Grenzen ----------
/// Ab dieser Gesamtzahl fragt die App nach, bevor weitere Dateien hinzukommen.
const SOFT_LIMIT: usize = 1000;
/// Dateien ab dieser Größe werden erst nach Bestätigung geladen (werden komplett in den RAM gelesen).
const LARGE_FILE: u64 = 500 * 1024 * 1024;
/// Feste Kartenhöhe – nötig für die virtualisierte Liste.
const CARD_H: f32 = 60.0;
/// Mindesthöhe der Dateiliste, bevor die Ansicht stattdessen scrollt.
const MIN_LIST: f32 = 110.0;
/// Platz für die Aktionsleiste unten (Knopfhöhe + Abstand).
const ACTION_BAR_H: f32 = 54.0;

// ---------- Zustand ----------
/// Fehlergrund – sprachunabhängig gespeichert, Text erst beim Anzeigen übersetzt.
#[derive(Debug, Clone, PartialEq)]
enum Fail {
    WrongPassword,
    PasswordMissing,
    Cancelled,
    Pdf(String),
    Io(String),
}

impl Fail {
    fn from_unlock(e: UnlockError) -> Self {
        match e {
            UnlockError::WrongPassword => Fail::WrongPassword,
            UnlockError::PasswordMissing => Fail::PasswordMissing,
            UnlockError::Pdf(s) => Fail::Pdf(s),
            UnlockError::Io(e) => Fail::Io(e.to_string()),
            UnlockError::NotEncrypted => Fail::Pdf("not encrypted".into()),
        }
    }

    fn text(&self, t: &Strings) -> String {
        match self {
            Fail::WrongPassword => t.err_wrong_password.into(),
            Fail::PasswordMissing => t.err_password_missing.into(),
            Fail::Cancelled => t.err_cancelled.into(),
            Fail::Pdf(e) => fill(t.err_pdf, "e", e),
            Fail::Io(e) => fill(t.err_io, "e", e),
        }
    }

    fn needs_password(&self) -> bool {
        matches!(self, Fail::WrongPassword | Fail::PasswordMissing)
    }
}

/// Arbeitsmodus der Oberfläche.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Unlock,
    Protect,
}

#[derive(Debug, Clone)]
enum Status {
    Checking,
    Large(u64),
    Ready(Protection),
    Queued,
    Working,
    Done(PathBuf, Mode),
    Failed(Fail),
}

struct Entry {
    path: PathBuf,
    status: Status,
    protection: Option<Protection>,
    permissions: Option<Permissions>,
}

/// Aufträge an den einen Hintergrund-Worker – alles läuft strikt nacheinander.
enum Job {
    /// (Pfad, große Datei trotzdem laden)
    Inspect(Vec<(PathBuf, bool)>),
    Process {
        files: Vec<PathBuf>,
        /// `None` = entsperren, `Some` = mit diesen Einstellungen schützen
        protect: Option<ProtectOptions>,
        password: String,
        overwrite: bool,
        out_dir: Option<PathBuf>,
        cancel: Arc<AtomicBool>,
    },
}

enum Msg {
    Inspected(PathBuf, Status, Option<Permissions>),
    Started(PathBuf),
    Unlocked(PathBuf, Status),
    UnlockFinished { cancelled: Vec<PathBuf> },
}

struct Progress {
    done: usize,
    total: usize,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum View {
    Main,
    Settings,
}

pub struct App {
    entries: Vec<Entry>,
    index: HashMap<PathBuf, usize>,
    password: String,
    show_password: bool,
    overwrite: bool,
    out_dir: Option<PathBuf>,
    progress: Option<Progress>,
    /// Dateien, die auf Bestätigung warten (weiche Grenze überschritten)
    pending: Option<Vec<PathBuf>>,
    jobs: Sender<Job>,
    rx: Receiver<Msg>,
    view: View,
    mode: Mode,
    open_pw: String,
    owner_pw: String,
    show_new_pw: bool,
    allowed: Permissions,
    /// Höhe aller Elemente außer der Liste im letzten Bild (die Liste füllt den Rest)
    other_h: f32,
    settings: Settings,
    /// Einstellungen auf die Platte schreiben (in Tests aus)
    persist: bool,
    /// Beim Start erkannte Systemsprache (für „Auto“)
    detected_lang: Lang,
    lang: Lang,
    applied_dark: Option<bool>,
    theme_watch: ThemeWatcher,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, initial: Vec<PathBuf>) -> Self {
        Self::build(cc, initial, Settings::load(), true)
    }

    fn build(cc: &eframe::CreationContext<'_>, initial: Vec<PathBuf>, settings: Settings, persist: bool) -> Self {
        let (jobs, job_rx) = channel::<Job>();
        let (tx, rx) = channel::<Msg>();
        let ctx = cc.egui_ctx.clone();
        std::thread::spawn(move || worker(job_rx, tx, ctx));
        let detected_lang = Lang::detect();
        let mut app = Self {
            entries: Vec::new(),
            index: HashMap::new(),
            password: String::new(),
            show_password: false,
            overwrite: false,
            out_dir: None,
            progress: None,
            pending: None,
            jobs,
            rx,
            view: View::Main,
            mode: Mode::Unlock,
            open_pw: String::new(),
            owner_pw: String::new(),
            show_new_pw: false,
            allowed: ALL_PERMISSIONS,
            other_h: 360.0,
            settings,
            persist,
            detected_lang,
            lang: resolve_lang(settings.lang, detected_lang),
            applied_dark: None,
            theme_watch: if persist { ThemeWatcher::start(cc.egui_ctx.clone()) } else { ThemeWatcher::disabled() },
        };
        app.update_theme(&cc.egui_ctx);
        app.add_files(initial);
        app
    }

    fn t(&self) -> &'static Strings {
        self.lang.strings()
    }

    fn pal(&self) -> &'static Palette {
        if self.applied_dark.unwrap_or(true) { &DARK } else { &LIGHT }
    }

    /// Bestimmt das wirksame Theme und wendet es bei Änderung an (läuft jedes Bild – billig).
    fn update_theme(&mut self, ctx: &egui::Context) {
        self.theme_watch.set_active(self.settings.theme == ThemePref::Auto);
        let dark = match self.settings.theme {
            ThemePref::Dark => true,
            ThemePref::Light => false,
            // Windows/macOS melden das System-Theme über egui, Linux/X11 über den Portal-Wächter.
            ThemePref::Auto => {
                ctx.system_theme().map(|t| t == egui::Theme::Dark).or(self.theme_watch.is_dark()).unwrap_or(true)
            }
        };
        // Auch neu anwenden, wenn jemand anderes das Theme des Kontexts umgestellt hat.
        let ctx_dark = ctx.theme() == egui::Theme::Dark;
        if self.applied_dark != Some(dark) || ctx_dark != dark {
            self.applied_dark = Some(dark);
            apply_style(ctx, self.pal(), dark);
        }
    }

    fn set_settings(&mut self, s: Settings, ctx: &egui::Context) {
        if s == self.settings {
            return;
        }
        self.settings = s;
        self.lang = resolve_lang(s.lang, self.detected_lang);
        if self.persist {
            let _ = s.save();
        }
        self.update_theme(ctx);
    }

    fn busy(&self) -> bool {
        self.progress.is_some()
    }

    fn rebuild_index(&mut self) {
        self.index = self.entries.iter().enumerate().map(|(i, e)| (e.path.clone(), i)).collect();
    }

    fn entry_mut(&mut self, p: &Path) -> Option<&mut Entry> {
        self.index.get(p).copied().and_then(|i| self.entries.get_mut(i))
    }

    /// Filtert, entfernt Duplikate und prüft die weiche Grenze.
    fn add_files(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        let mut seen = HashSet::new();
        let new: Vec<PathBuf> = paths
            .into_iter()
            .filter(|p| {
                p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
                    && !self.index.contains_key(p)
                    && p.is_file()
                    && seen.insert(p.clone())
            })
            .collect();
        if new.is_empty() {
            return;
        }
        if self.entries.len() + new.len() > SOFT_LIMIT {
            self.pending = Some(new);
        } else {
            self.commit_files(new);
        }
    }

    fn commit_files(&mut self, new: Vec<PathBuf>) {
        for p in &new {
            self.index.insert(p.clone(), self.entries.len());
            self.entries.push(Entry { path: p.clone(), status: Status::Checking, protection: None, permissions: None });
        }
        let _ = self.jobs.send(Job::Inspect(new.into_iter().map(|p| (p, false)).collect()));
    }

    fn allow_large(&mut self, p: PathBuf) {
        if let Some(e) = self.entry_mut(&p) {
            e.status = Status::Checking;
        }
        let _ = self.jobs.send(Job::Inspect(vec![(p, true)]));
    }

    fn protect_options(&self) -> ProtectOptions {
        ProtectOptions {
            open_password: self.open_pw.clone(),
            owner_password: self.owner_pw.clone(),
            permissions: self.allowed,
        }
    }

    fn start(&mut self) {
        let mode = self.mode;
        if mode == Mode::Protect && !self.protect_options().is_effective() {
            return;
        }
        let files: Vec<PathBuf> = self
            .entries
            .iter_mut()
            .filter(|e| is_actionable(&e.status, mode))
            .map(|e| {
                e.status = Status::Queued;
                e.path.clone()
            })
            .collect();
        if files.is_empty() {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.progress = Some(Progress { done: 0, total: files.len(), cancel: cancel.clone() });
        let _ = self.jobs.send(Job::Process {
            files,
            protect: (mode == Mode::Protect).then(|| self.protect_options()),
            password: self.password.clone(),
            overwrite: self.overwrite,
            out_dir: self.out_dir.clone(),
            cancel,
        });
    }

    fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Inspected(p, st, perms) => {
                    if let Some(e) = self.entry_mut(&p) {
                        if let Status::Ready(pr) = st {
                            e.protection = Some(pr);
                        }
                        e.permissions = perms;
                        e.status = st;
                    }
                }
                Msg::Started(p) => {
                    if let Some(e) = self.entry_mut(&p) {
                        e.status = Status::Working;
                    }
                }
                Msg::Unlocked(p, st) => {
                    if let Some(pr) = &mut self.progress {
                        pr.done += 1;
                    }
                    if let Some(e) = self.entry_mut(&p) {
                        e.status = st;
                    }
                }
                Msg::UnlockFinished { cancelled } => {
                    for p in cancelled {
                        if let Some(e) = self.entry_mut(&p) {
                            e.status = match e.protection {
                                Some(pr) => Status::Ready(pr),
                                None => Status::Failed(Fail::Cancelled),
                            };
                        }
                    }
                    self.progress = None;
                }
            }
        }
    }

    fn actionable(&self) -> usize {
        self.entries.iter().filter(|e| is_actionable(&e.status, self.mode)).count()
    }

    /// Passwortfeld nur zeigen, wenn eine Datei wirklich eins zum Öffnen braucht.
    fn needs_password(&self) -> bool {
        self.entries.iter().any(|e| match &e.status {
            Status::Ready(Protection::PasswordRequired) => true,
            Status::Failed(f) => f.needs_password(),
            _ => false,
        })
    }
}

fn resolve_lang(pref: LangPref, detected: Lang) -> Lang {
    match pref {
        LangPref::Auto => detected,
        LangPref::Fixed(l) => l,
    }
}

fn is_actionable(st: &Status, mode: Mode) -> bool {
    match mode {
        Mode::Unlock => {
            matches!(st, Status::Ready(Protection::RestrictionsOnly | Protection::PasswordRequired) | Status::Failed(_))
        }
        Mode::Protect => matches!(st, Status::Ready(_) | Status::Failed(_)),
    }
}

/// Der einzige Hintergrund-Thread: arbeitet Aufträge nacheinander ab,
/// dadurch ist immer höchstens eine PDF gleichzeitig im Speicher.
fn worker(jobs: Receiver<Job>, tx: Sender<Msg>, ctx: egui::Context) {
    let send = |m: Msg| {
        let _ = tx.send(m);
        ctx.request_repaint();
    };
    while let Ok(job) = jobs.recv() {
        match job {
            Job::Inspect(files) => {
                for (p, force) in files {
                    let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    let msg = if size > LARGE_FILE && !force {
                        Msg::Inspected(p, Status::Large(size), None)
                    } else {
                        match core::inspect(&p) {
                            Ok(i) => Msg::Inspected(p, Status::Ready(i.protection), i.permissions),
                            Err(e) => Msg::Inspected(p, Status::Failed(Fail::from_unlock(e)), None),
                        }
                    };
                    send(msg);
                }
            }
            Job::Process { files, protect, password, overwrite, out_dir, cancel } => {
                let mut cancelled = Vec::new();
                for (i, p) in files.iter().enumerate() {
                    if cancel.load(Ordering::Relaxed) {
                        cancelled = files[i..].to_vec();
                        break;
                    }
                    send(Msg::Started(p.clone()));
                    let st = match &protect {
                        None => {
                            let target =
                                if overwrite { p.clone() } else { core::default_output(p, out_dir.as_deref()) };
                            match core::unlock(p, &target, Some(&password)) {
                                Ok(_) => Status::Done(target, Mode::Unlock),
                                Err(UnlockError::NotEncrypted) => Status::Ready(Protection::None),
                                Err(e) => Status::Failed(Fail::from_unlock(e)),
                            }
                        }
                        Some(opts) => {
                            let target =
                                if overwrite { p.clone() } else { core::protected_output(p, out_dir.as_deref()) };
                            match core::protect(p, &target, opts, Some(&password)) {
                                Ok(()) => Status::Done(target, Mode::Protect),
                                Err(e) => Status::Failed(Fail::from_unlock(e)),
                            }
                        }
                    };
                    send(Msg::Unlocked(p.clone(), st));
                }
                send(Msg::UnlockFinished { cancelled });
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll();
        let ctx = ui.ctx().clone();
        self.update_theme(&ctx);
        let pal = self.pal();

        // Drag & Drop (nicht während der Verarbeitung oder einer offenen Rückfrage)
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
        if !dropped.is_empty() && !self.busy() && self.pending.is_none() {
            self.view = View::Main;
            self.add_files(dropped);
        }
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());
        if self.view == View::Settings && ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.view = View::Main;
        }

        egui::CentralPanel::default().frame(Frame::new().fill(pal.bg).inner_margin(Margin::symmetric(28, 24))).show(
            ui,
            |ui| {
                self.header(ui);
                ui.add_space(18.0);
                match self.view {
                    View::Settings => self.settings_view(ui, &ctx),
                    View::Main => {
                        // Aktionsleiste ist immer sichtbar; der Bereich darüber scrollt, wenn das
                        // Fenster zu niedrig ist. Die Liste bekommt den freien Platz, mindestens MIN_LIST.
                        let viewport = (ui.available_height() - ACTION_BAR_H).max(MIN_LIST);
                        egui::ScrollArea::vertical()
                            .id_salt("main_scroll")
                            .max_height(viewport)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                self.mode_switch(ui);
                                ui.add_space(12.0);
                                self.drop_zone(ui, hovering);
                                ui.add_space(12.0);
                                let list_h = (viewport - self.other_h).max(MIN_LIST);
                                ui.allocate_ui(Vec2::new(ui.available_width(), list_h), |ui| self.file_list(ui));
                                ui.add_space(10.0);
                                self.controls(ui);
                                // Höhe aller übrigen Elemente merken (wirkt ab dem nächsten Bild)
                                let other = ui.min_rect().height() - list_h;
                                if (other - self.other_h).abs() > 0.5 {
                                    self.other_h = other;
                                    ctx.request_repaint();
                                }
                            });
                        ui.add_space(12.0);
                        self.action_bar(ui);
                    }
                }
            },
        );

        self.limit_dialog(&ctx);
    }
}

// ---------- UI-Bausteine ----------
impl App {
    fn header(&mut self, ui: &mut egui::Ui) {
        let (pal, t) = (self.pal(), self.t());
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
            ui.painter().rect_filled(rect, CornerRadius::same(12), pal.accent);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "🔓",
                FontId::proportional(22.0),
                Color32::WHITE,
            );
            ui.add_space(8.0);
            // Platz für den ⚙-Knopf rechts freihalten; lange Untertitel brechen um.
            let text_w = (ui.available_width() - 50.0).max(120.0);
            ui.vertical(|ui| {
                ui.set_max_width(text_w);
                ui.label(RichText::new("Doclatch").size(22.0).strong().color(pal.text));
                ui.add(egui::Label::new(RichText::new(t.subtitle).size(13.0).color(pal.muted)).wrap());
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let active = self.view == View::Settings;
                let b = egui::Button::new(RichText::new("⚙").size(18.0).color(if active {
                    Color32::WHITE
                } else {
                    pal.text
                }))
                .fill(if active { pal.accent } else { pal.surface_hi })
                .corner_radius(CornerRadius::same(10))
                .min_size(Vec2::splat(34.0));
                if ui.add(b).on_hover_text(t.settings).clicked() {
                    self.view = if active { View::Main } else { View::Settings };
                }
            });
        });
    }

    /// Umschalter „Entsperren | Schützen“ über die volle Breite.
    fn mode_switch(&mut self, ui: &mut egui::Ui) {
        let (pal, t) = (self.pal(), self.t());
        let busy = self.busy();
        Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.border))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(4))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                let w = (ui.available_width() - 4.0) / 2.0;
                ui.horizontal(|ui| {
                    for (mode, icon, label) in [(Mode::Unlock, "🔓", t.unlock), (Mode::Protect, "🔒", t.protect)] {
                        let sel = self.mode == mode;
                        let b = egui::Button::new(RichText::new(format!("{icon}  {label}")).strong().color(if sel {
                            Color32::WHITE
                        } else {
                            pal.muted
                        }))
                        .fill(if sel { pal.accent } else { Color32::TRANSPARENT })
                        .stroke(Stroke::NONE)
                        .corner_radius(CornerRadius::same(9))
                        .min_size(Vec2::new(w, 32.0));
                        if ui.add_enabled(!busy || sel, b).clicked() {
                            self.mode = mode;
                        }
                    }
                });
            });
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui, hovering: bool) {
        let (pal, t) = (self.pal(), self.t());
        // Sobald Dateien da sind, wird das Feld flacher – mehr Platz für Liste und Einstellungen.
        let compact = !self.entries.is_empty();
        let height = if compact { 64.0 } else { 120.0 };
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::click());
        let active = hovering || (resp.hovered() && !self.busy());
        let (fill_c, stroke) = if active {
            (pal.accent.gamma_multiply(0.10), Stroke::new(1.5, pal.accent))
        } else {
            (pal.surface, Stroke::new(1.0, pal.border))
        };
        let p = ui.painter();
        p.rect(rect, CornerRadius::same(16), fill_c, stroke, StrokeKind::Inside);
        dashed_border(p, rect.shrink(8.0), if active { pal.accent } else { pal.border });
        if compact {
            let title = if hovering { t.drop_release } else { t.drop_title };
            p.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                format!("📄  {title}"),
                FontId::proportional(14.0),
                if active { pal.accent_hi } else { pal.text },
            );
        } else {
            p.text(
                rect.center() - Vec2::new(0.0, 16.0),
                egui::Align2::CENTER_CENTER,
                "📄",
                FontId::proportional(28.0),
                if active { pal.accent_hi } else { pal.muted },
            );
            p.text(
                rect.center() + Vec2::new(0.0, 16.0),
                egui::Align2::CENTER_CENTER,
                if hovering { t.drop_release } else { t.drop_title },
                FontId::proportional(15.0),
                pal.text,
            );
            p.text(
                rect.center() + Vec2::new(0.0, 36.0),
                egui::Align2::CENTER_CENTER,
                t.drop_hint,
                FontId::proportional(12.0),
                pal.muted,
            );
        }
        if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked()
            && !self.busy()
            && self.pending.is_none()
            && let Some(files) = rfd::FileDialog::new().add_filter("PDF", &["pdf", "PDF"]).pick_files()
        {
            self.add_files(files);
        }
    }

    fn file_list(&mut self, ui: &mut egui::Ui) {
        let (pal, t) = (self.pal(), self.t());
        if self.entries.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(RichText::new(t.empty_list).color(pal.muted));
            });
            return;
        }
        // Kopfzeile mit Zählern
        let checking = self.entries.iter().filter(|e| matches!(e.status, Status::Checking)).count();
        let mut info = fill(t.files_count, "n", self.entries.len());
        if checking > 0 {
            info += &format!("  ·  {}", fill(t.checking_count, "n", checking));
        }
        let mut clear_all = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(info).size(12.0).color(pal.muted));
            if !self.busy() {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let b = egui::Button::new(RichText::new(t.clear_list).size(12.0).color(pal.muted)).frame(false);
                    clear_all = ui.add(b).clicked();
                });
            }
        });
        ui.add_space(4.0);

        let mut remove = None;
        let mut allow = None;
        let busy = self.busy();
        // Virtualisiert: nur sichtbare Zeilen werden aufgebaut und gezeichnet.
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(
            ui,
            CARD_H,
            self.entries.len(),
            |ui, range| {
                for i in range {
                    let e = &self.entries[i];
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), CARD_H), Sense::hover());
                    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                        Frame::new()
                            .fill(pal.surface)
                            .stroke(Stroke::new(1.0, pal.border))
                            .corner_radius(CornerRadius::same(12))
                            .inner_margin(Margin::symmetric(14, 10))
                            .show(ui, |ui| {
                                let row = Vec2::new(ui.available_width(), CARD_H - 22.0);
                                ui.allocate_ui_with_layout(row, Layout::right_to_left(Align::Center), |ui| {
                                    if !busy {
                                        let x = egui::Button::new(RichText::new("×").size(18.0).color(pal.muted))
                                            .frame(false);
                                        if ui.add(x).on_hover_text(t.remove).clicked() {
                                            remove = Some(i);
                                        }
                                    }
                                    let b = badge(ui, pal, t, &e.status);
                                    // Berechtigungen als Info beim Überfahren
                                    if let Status::Ready(
                                        pr @ (Protection::RestrictionsOnly | Protection::PasswordRequired),
                                    ) = e.status
                                    {
                                        b.on_hover_cursor(egui::CursorIcon::Help).on_hover_ui(|ui| {
                                            perms_tooltip(
                                                ui,
                                                pal,
                                                t,
                                                e.permissions,
                                                pr == Protection::PasswordRequired,
                                            );
                                        });
                                    }
                                    if matches!(e.status, Status::Large(_)) && !busy {
                                        let b = egui::Button::new(RichText::new(t.load_anyway).size(12.0))
                                            .fill(pal.surface_hi)
                                            .corner_radius(CornerRadius::same(8));
                                        if ui.add(b).on_hover_text(t.load_anyway_tip).clicked() {
                                            allow = Some(e.path.clone());
                                        }
                                    }
                                    ui.add_space(6.0);
                                    ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                                        ui.label(RichText::new("📄").size(20.0).color(pal.accent));
                                        ui.vertical(|ui| {
                                            let name =
                                                e.path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
                                            ui.add(
                                                egui::Label::new(RichText::new(name).strong().color(pal.text))
                                                    .truncate(),
                                            );
                                            let sub = match &e.status {
                                                Status::Done(out, _) => fill(t.saved_to, "path", out.display()),
                                                Status::Failed(f) => f.text(t),
                                                Status::Large(_) => t.large_note.to_string(),
                                                _ => parent_display(&e.path),
                                            };
                                            let col = match e.status {
                                                Status::Failed(_) => pal.error,
                                                Status::Large(_) => pal.warn,
                                                _ => pal.muted,
                                            };
                                            ui.add(
                                                egui::Label::new(RichText::new(sub).size(12.0).color(col)).truncate(),
                                            );
                                        });
                                    });
                                });
                            });
                    });
                }
            },
        );
        if clear_all {
            self.entries.clear();
            self.index.clear();
        } else if let Some(i) = remove {
            self.entries.remove(i);
            self.rebuild_index();
        }
        if let Some(p) = allow {
            self.allow_large(p);
        }
    }

    /// Rückfrage, wenn die weiche Grenze überschritten würde.
    fn limit_dialog(&mut self, ctx: &egui::Context) {
        let Some(pending) = &self.pending else { return };
        let (pal, t) = (self.pal(), self.t());
        let (n, total) = (pending.len(), self.entries.len() + pending.len());
        let room = SOFT_LIMIT.saturating_sub(self.entries.len());
        let mut choice = None; // Some(Some(k)) = k hinzufügen, Some(None) = abbrechen

        let modal = egui::Modal::new(egui::Id::unique("soft_limit")).frame(
            Frame::new()
                .fill(pal.surface)
                .stroke(Stroke::new(1.0, pal.border))
                .corner_radius(CornerRadius::same(16))
                .inner_margin(Margin::same(22)),
        );
        let resp = modal.show(ctx, |ui| {
            ui.set_width(420.0);
            ui.label(RichText::new(t.many_title).size(18.0).strong().color(pal.text));
            ui.add_space(8.0);
            let body = fill(&fill(t.many_body, "n", n), "total", total);
            ui.label(RichText::new(body).color(pal.muted));
            ui.add_space(16.0);
            ui.horizontal_wrapped(|ui| {
                let primary = egui::Button::new(RichText::new(fill(t.add_all, "n", n)).color(Color32::WHITE).strong())
                    .fill(pal.accent)
                    .corner_radius(CornerRadius::same(8));
                if ui.add(primary).clicked() {
                    choice = Some(Some(n));
                }
                if room > 0 && room < n {
                    let b = egui::Button::new(fill(t.add_only, "n", room))
                        .fill(pal.surface_hi)
                        .corner_radius(CornerRadius::same(8));
                    if ui.add(b).on_hover_text(fill(t.add_only_tip, "n", SOFT_LIMIT)).clicked() {
                        choice = Some(Some(room));
                    }
                }
                let cancel = egui::Button::new(t.cancel).fill(pal.surface_hi).corner_radius(CornerRadius::same(8));
                if ui.add(cancel).clicked() {
                    choice = Some(None);
                }
            });
        });
        if resp.should_close() && choice.is_none() {
            choice = Some(None);
        }
        if let Some(c) = choice {
            let mut files = self.pending.take().unwrap_or_default();
            if let Some(k) = c {
                files.truncate(k);
                self.commit_files(files);
            }
        }
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        let (pal, t) = (self.pal(), self.t());
        let needs_pw = self.needs_password();
        let protect = self.mode == Mode::Protect;

        Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.border))
            .corner_radius(CornerRadius::same(14))
            .inner_margin(Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                let row = Vec2::new(ui.available_width(), 32.0);
                if needs_pw {
                    ui.allocate_ui_with_layout(row, Layout::left_to_right(Align::Center), |ui| {
                        ui.label(RichText::new(if protect { t.current_password } else { t.password }).color(pal.muted));
                        let w = ui.available_width() - 44.0;
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(!self.show_password)
                                .hint_text(t.pw_hint)
                                .margin(Margin::symmetric(10, 7))
                                .desired_width(w),
                        );
                        let eye = egui::Button::new(if self.show_password { "🙈" } else { "👁" })
                            .fill(pal.surface_hi)
                            .corner_radius(CornerRadius::same(8));
                        if ui.add(eye).on_hover_text(t.show_password).clicked() {
                            self.show_password = !self.show_password;
                        }
                    });
                    ui.add_space(8.0);
                }
                if protect {
                    self.protect_settings(ui);
                    ui.add_space(8.0);
                }
                ui.allocate_ui_with_layout(row, Layout::left_to_right(Align::Center), |ui| {
                    ui.checkbox(&mut self.overwrite, RichText::new(t.overwrite).color(pal.text));
                    ui.add_space(12.0);
                    ui.add_enabled_ui(!self.overwrite, |ui| {
                        let label = match &self.out_dir {
                            Some(d) => format!("📁 {}", d.display()),
                            None => format!("📁 {}", t.save_next_to),
                        };
                        let b = egui::Button::new(RichText::new(label).size(13.0))
                            .fill(pal.surface_hi)
                            .corner_radius(CornerRadius::same(8));
                        if ui.add(b).on_hover_text(t.choose_folder).clicked()
                            && let Some(d) = rfd::FileDialog::new().pick_folder()
                        {
                            self.out_dir = Some(d);
                        }
                        if self.out_dir.is_some() && ui.small_button("×").on_hover_text(t.reset).clicked() {
                            self.out_dir = None;
                        }
                    });
                });
            });
    }

    /// Fortschritt/Abbrechen bzw. Hauptknopf – fest am unteren Rand.
    fn action_bar(&mut self, ui: &mut egui::Ui) {
        let (pal, t) = (self.pal(), self.t());
        let protect = self.mode == Mode::Protect;
        ui.horizontal(|ui| {
            if let Some(pr) = &self.progress {
                // Fortschritt + Abbrechen
                let (done, total) = (pr.done, pr.total);
                let cancelling = pr.cancel.load(Ordering::Relaxed);
                let cancel_btn =
                    egui::Button::new(RichText::new(if cancelling { t.cancelling } else { t.cancel }).color(pal.text))
                        .fill(pal.surface_hi)
                        .corner_radius(CornerRadius::same(10))
                        .min_size(Vec2::new(150.0, 42.0));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add_enabled(!cancelling, cancel_btn).clicked() {
                        pr.cancel.store(true, Ordering::Relaxed);
                    }
                    ui.add_space(8.0);
                    ui.add(
                        egui::ProgressBar::new(done as f32 / total.max(1) as f32)
                            .text(format!("{done} / {total}"))
                            .fill(pal.accent)
                            .desired_height(42.0)
                            .corner_radius(CornerRadius::same(10)),
                    );
                });
                return;
            }

            let n = self.actionable();
            let done = self.entries.iter().filter(|e| matches!(e.status, Status::Done(..))).count();
            if done > 0 {
                let clear = egui::Button::new(RichText::new(t.clear_done).color(pal.muted))
                    .fill(pal.surface_hi)
                    .corner_radius(CornerRadius::same(10))
                    .min_size(Vec2::new(0.0, 42.0));
                if ui.add(clear).clicked() {
                    self.entries.retain(|e| !matches!(e.status, Status::Done(..)));
                    self.rebuild_index();
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (icon, one, many) =
                    if protect { ("🔒", t.protect, t.protect_n) } else { ("🔓", t.unlock, t.unlock_n) };
                let text = if n == 0 { one.to_string() } else { format!("{icon}  {}", fill(many, "n", n)) };
                let effective = !protect || self.protect_options().is_effective();
                let enabled = n > 0 && self.pending.is_none() && effective;
                let btn = egui::Button::new(RichText::new(text).size(15.0).strong().color(Color32::WHITE))
                    .fill(if enabled { pal.accent } else { pal.accent.gamma_multiply(0.35) })
                    .corner_radius(CornerRadius::same(10))
                    .min_size(Vec2::new(220.0, 42.0));
                let mut r = ui.add_enabled(enabled, btn);
                if !effective {
                    r = r.on_disabled_hover_text(t.nothing_to_protect);
                }
                if r.clicked() || (enabled && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    self.start();
                }
                // Grund für den gesperrten Knopf direkt sichtbar machen (links daneben, umbrechend)
                if !effective && n > 0 {
                    ui.add_space(8.0);
                    ui.add(egui::Label::new(RichText::new(t.nothing_to_protect).size(12.0).color(pal.warn)).wrap());
                }
            });
        });
    }

    /// Passwörter und erlaubte Aktionen für den Schutz-Modus.
    fn protect_settings(&mut self, ui: &mut egui::Ui) {
        let (pal, t) = (self.pal(), self.t());
        let label_w = 150.0;
        let show = self.show_new_pw;
        let mut toggle = false;
        for (i, (label, hint)) in
            [(t.open_password, t.open_pw_hint), (t.owner_password, t.owner_pw_hint)].into_iter().enumerate()
        {
            let row = Vec2::new(ui.available_width(), 32.0);
            ui.allocate_ui_with_layout(row, Layout::left_to_right(Align::Center), |ui| {
                ui.allocate_ui_with_layout(Vec2::new(label_w, 20.0), Layout::left_to_right(Align::Center), |ui| {
                    ui.set_min_width(label_w);
                    ui.add(egui::Label::new(RichText::new(label).color(pal.muted)).truncate());
                });
                let w = ui.available_width() - if i == 0 { 44.0 } else { 0.0 };
                let text = if i == 0 { &mut self.open_pw } else { &mut self.owner_pw };
                ui.add(
                    egui::TextEdit::singleline(text)
                        .password(!show)
                        .hint_text(hint)
                        .margin(Margin::symmetric(10, 7))
                        .desired_width(w),
                );
                if i == 0 {
                    let eye = egui::Button::new(if show { "🙈" } else { "👁" })
                        .fill(pal.surface_hi)
                        .corner_radius(CornerRadius::same(8));
                    toggle = ui.add(eye).on_hover_text(t.show_password).clicked();
                }
            });
            ui.add_space(4.0);
        }
        if toggle {
            self.show_new_pw = !self.show_new_pw;
        }
        if !self.open_pw.is_empty() {
            ui.label(RichText::new(format!("🔐 {}", t.keep_password)).size(12.0).color(pal.warn));
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new(t.allowed).strong().color(pal.text));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button(t.allow_none).clicked() {
                    self.allowed = Permissions::empty();
                }
                if ui.small_button(t.allow_all).clicked() {
                    self.allowed = ALL_PERMISSIONS;
                }
            });
        });
        egui::Grid::new("perms").num_columns(2).spacing([16.0, 2.0]).show(ui, |ui| {
            for (i, (flag, name)) in perm_list(t).into_iter().enumerate() {
                let mut on = self.allowed.contains(flag);
                if ui.checkbox(&mut on, RichText::new(name).size(13.0).color(pal.text)).changed() {
                    self.allowed.set(flag, on);
                }
                if i % 2 == 1 {
                    ui.end_row();
                }
            }
        });
        ui.add_space(2.0);
        ui.label(RichText::new(t.protect_note).size(11.5).color(pal.muted));
    }

    fn settings_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let (pal, t) = (self.pal(), self.t());
        let mut s = self.settings;
        let detected = self.detected_lang;

        ui.horizontal(|ui| {
            let back = egui::Button::new(RichText::new(format!("⬅  {}", t.back)).color(pal.text))
                .fill(pal.surface_hi)
                .corner_radius(CornerRadius::same(8));
            if ui.add(back).clicked() {
                self.view = View::Main;
            }
            ui.add_space(8.0);
            ui.label(RichText::new(t.settings).size(18.0).strong().color(pal.text));
        });
        ui.add_space(14.0);

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            card(ui, pal, |ui| {
                section_title(ui, pal, "🎨", t.appearance);
                ui.horizontal(|ui| {
                    for (pref, label) in [
                        (ThemePref::Auto, t.theme_auto),
                        (ThemePref::Dark, t.theme_dark),
                        (ThemePref::Light, t.theme_light),
                    ] {
                        if segment(ui, pal, label, s.theme == pref).clicked() {
                            s.theme = pref;
                        }
                    }
                });
                ui.add_space(4.0);
                ui.label(RichText::new(t.theme_auto_hint).size(12.0).color(pal.muted));
            });
            ui.add_space(10.0);

            card(ui, pal, |ui| {
                section_title(ui, pal, "🌐", t.language);
                let auto_label = fill(t.lang_auto, "lang", detected.native_name());
                let current = match s.lang {
                    LangPref::Auto => auto_label.clone(),
                    LangPref::Fixed(l) => l.native_name().to_string(),
                };
                egui::ComboBox::from_id_salt("language").selected_text(current).width(260.0).show_ui(ui, |ui| {
                    ui.selectable_value(&mut s.lang, LangPref::Auto, auto_label);
                    for l in Lang::ALL {
                        ui.selectable_value(&mut s.lang, LangPref::Fixed(l), l.native_name());
                    }
                });
            });
            ui.add_space(10.0);

            card(ui, pal, |ui| {
                section_title(ui, pal, "ℹ", t.about);
                ui.label(
                    RichText::new(format!("Doclatch {}  ·  {}", env!("CARGO_PKG_VERSION"), env!("CARGO_PKG_LICENSE")))
                        .strong()
                        .color(pal.text),
                );
                ui.label(RichText::new(t.about_local).color(pal.text));
                ui.add_space(4.0);
                ui.label(RichText::new(t.translation_note).size(12.0).color(pal.muted));
                ui.label(RichText::new(t.licenses_note).size(12.0).color(pal.muted));
            });
            ui.add_space(10.0);

            card(ui, pal, |ui| {
                section_title(ui, pal, "🛡", t.disclaimer_title);
                ui.label(RichText::new(t.disclaimer).color(pal.text));
            });
        });

        self.set_settings(s, ctx);
    }
}

fn card(ui: &mut egui::Ui, pal: &Palette, add: impl FnOnce(&mut egui::Ui)) {
    Frame::new()
        .fill(pal.surface)
        .stroke(Stroke::new(1.0, pal.border))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui);
        });
}

fn section_title(ui: &mut egui::Ui, pal: &Palette, icon: &str, title: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon).size(16.0).color(pal.accent));
        ui.label(RichText::new(title).size(15.0).strong().color(pal.text));
    });
    ui.add_space(6.0);
}

/// Segment-Schalter (z. B. Auto | Dunkel | Hell).
fn segment(ui: &mut egui::Ui, pal: &Palette, label: &str, selected: bool) -> egui::Response {
    let b = egui::Button::new(RichText::new(label).color(if selected { Color32::WHITE } else { pal.text }))
        .fill(if selected { pal.accent } else { pal.surface_hi })
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(96.0, 32.0));
    ui.add(b)
}

fn perm_list(t: &Strings) -> [(Permissions, &'static str); 8] {
    [
        (Permissions::PRINTABLE, t.perm_print),
        (Permissions::PRINTABLE_IN_HIGH_QUALITY, t.perm_print_hq),
        (Permissions::MODIFIABLE, t.perm_modify),
        (Permissions::COPYABLE, t.perm_copy),
        (Permissions::ANNOTABLE, t.perm_annotate),
        (Permissions::FILLABLE, t.perm_fill),
        (Permissions::COPYABLE_FOR_ACCESSIBILITY, t.perm_accessibility),
        (Permissions::ASSEMBLABLE, t.perm_assemble),
    ]
}

fn perms_tooltip(ui: &mut egui::Ui, pal: &Palette, t: &Strings, perms: Option<Permissions>, needs_open: bool) {
    ui.set_max_width(320.0);
    if needs_open {
        ui.label(RichText::new(format!("🔒 {}", t.needs_open_password)).color(pal.warn));
        ui.add_space(4.0);
    }
    ui.label(RichText::new(t.perms_title).strong().color(pal.text));
    match perms {
        Some(p) => {
            for (flag, name) in perm_list(t) {
                let ok = p.contains(flag);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(if ok { "✔" } else { "✖" }).color(if ok { pal.success } else { pal.error }));
                    ui.label(RichText::new(name).color(pal.text));
                });
            }
        }
        None => {
            ui.label(RichText::new(t.perm_unknown).color(pal.muted));
        }
    }
    ui.add_space(4.0);
    ui.label(RichText::new(t.unlock_removes_all).size(12.0).color(pal.muted));
}

fn human_size(b: u64) -> String {
    let mb = b as f64 / (1024.0 * 1024.0);
    if mb >= 1024.0 { format!("{:.1} GB", mb / 1024.0) } else { format!("{mb:.0} MB") }
}

fn badge(ui: &mut egui::Ui, pal: &Palette, t: &Strings, st: &Status) -> egui::Response {
    let (text, color) = match st {
        Status::Checking => (t.st_checking.to_string(), pal.muted),
        Status::Large(b) => (fill(t.st_large, "size", human_size(*b)), pal.warn),
        Status::Ready(Protection::None) => (t.st_none.to_string(), pal.muted),
        Status::Ready(Protection::RestrictionsOnly) => (format!("{}  ℹ", t.st_restricted), pal.warn),
        Status::Ready(Protection::PasswordRequired) => (format!("🔒 {}", t.st_password), pal.warn),
        Status::Queued => (t.st_queued.to_string(), pal.muted),
        Status::Working => (t.st_working.to_string(), pal.accent_hi),
        Status::Done(_, Mode::Unlock) => (format!("✔ {}", t.st_done), pal.success),
        Status::Done(_, Mode::Protect) => (format!("🔒 {}", t.st_protected), pal.success),
        Status::Failed(_) => (t.st_failed.to_string(), pal.error),
    };
    Frame::new()
        .fill(color.gamma_multiply(0.15))
        .corner_radius(CornerRadius::same(255))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(12.0).strong().color(color));
        })
        .response
}

fn parent_display(p: &Path) -> String {
    p.parent().map(|d| d.display().to_string()).unwrap_or_default()
}

fn dashed_border(p: &egui::Painter, r: egui::Rect, color: Color32) {
    let stroke = Stroke::new(1.0, color.gamma_multiply(0.6));
    let (dash, gap) = (6.0, 5.0);
    let pts = [r.left_top(), r.right_top(), r.right_bottom(), r.left_bottom(), r.left_top()];
    for w in pts.windows(2) {
        p.extend(egui::Shape::dashed_line(&[w[0], w[1]], stroke, dash, gap));
    }
}

fn apply_style(ctx: &egui::Context, pal: &Palette, dark: bool) {
    // egui führt getrennte Stile für Hell und Dunkel – das gewählte aktiv setzen, dann anpassen.
    ctx.set_theme(if dark { egui::Theme::Dark } else { egui::Theme::Light });
    let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    v.panel_fill = pal.bg;
    v.window_fill = pal.surface;
    v.window_stroke = Stroke::new(1.0, pal.border);
    v.extreme_bg_color = pal.surface_hi; // Textfelder
    v.override_text_color = Some(pal.text);
    v.selection.bg_fill = pal.accent.gamma_multiply(0.5);
    v.selection.stroke = Stroke::new(1.0, pal.accent_hi);
    v.hyperlink_color = pal.accent_hi;
    let r = CornerRadius::same(8);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
    }
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, pal.border);
    v.widgets.inactive.weak_bg_fill = pal.surface_hi;
    v.widgets.hovered.weak_bg_fill = pal.surface_hi;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, pal.accent);
    v.widgets.active.bg_stroke = Stroke::new(1.0, pal.accent_hi);
    v.widgets.inactive.bg_fill = pal.surface_hi; // Checkbox-Kästchen
    v.widgets.hovered.bg_fill = pal.surface_hi;
    ctx.set_visuals(v);
    ctx.all_styles_mut(|s| {
        s.spacing.item_spacing = Vec2::new(8.0, 6.0);
        s.spacing.button_padding = Vec2::new(12.0, 6.0);
        s.text_styles.insert(egui::TextStyle::Body, FontId::proportional(14.0));
        s.text_styles.insert(egui::TextStyle::Button, FontId::proportional(14.0));
    });
}

fn app_icon() -> egui::IconData {
    // Einfaches generiertes Icon: violettes, abgerundetes Quadrat mit hellem Schloss-Bügel.
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let rr = 14.0;
            let cx = fx.clamp(rr, n as f32 - rr);
            let cy = fy.clamp(rr, n as f32 - rr);
            let inside = (fx - cx).powi(2) + (fy - cy).powi(2) <= rr * rr;
            let i = (y * n + x) * 4;
            if !inside {
                continue;
            }
            let t = fy / n as f32;
            let mut c = [(0x7C as f32 * (1.0 - t) + 0x5A as f32 * t) as u8, 0x5C, 0xFF, 255];
            // Schlosskörper
            let body = (18.0..46.0).contains(&fx) && (30.0..50.0).contains(&fy);
            // offener Bügel (nach rechts verschoben)
            let d = ((fx - 36.0).powi(2) + (fy - 26.0).powi(2)).sqrt();
            let shackle = (7.0..11.0).contains(&d) && fy <= 30.0;
            if body || shackle {
                c = [255, 255, 255, 255];
            }
            rgba[i..i + 4].copy_from_slice(&c);
        }
    }
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

/// Reihenfolge der Grafik-Backends. Schlägt eines fehl (z. B. kein OpenGL ≥ 2 in einer VM),
/// wird das nächste versucht. Mit `DOCLATCH_RENDERER=glow|wgpu` lässt sich eines erzwingen.
fn renderers() -> Vec<eframe::Renderer> {
    let all = vec![
        #[cfg(windows)]
        eframe::Renderer::Wgpu, // DirectX 12, mit WARP-Software-Fallback
        eframe::Renderer::Glow,
    ];
    match std::env::var("DOCLATCH_RENDERER").ok().as_deref() {
        Some(name) => all.into_iter().filter(|r| r.to_string() == name).collect(),
        None => all,
    }
}

pub fn run(initial: Vec<PathBuf>) -> eframe::Result {
    let mut last_err = None;
    for renderer in renderers() {
        let options = eframe::NativeOptions {
            renderer,
            viewport: egui::ViewportBuilder::default()
                .with_title("Doclatch")
                .with_inner_size([680.0, 780.0])
                .with_min_inner_size([540.0, 620.0])
                .with_drag_and_drop(true)
                .with_icon(app_icon()),
            ..Default::default()
        };
        let files = initial.clone();
        match eframe::run_native("Doclatch", options, Box::new(|cc| Ok(Box::new(App::new(cc, files))))) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("Graphics backend “{renderer}” not available: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| eframe::Error::AppCreation("no suitable graphics backend".into())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tests::{encrypted_file, tmpdir};
    use crate::i18n::{DE, EN};
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;

    /// Erzeugt `n` kleine PDFs mit Rechte-Einschränkungen.
    fn make_pdfs(tag: &str, n: usize) -> (PathBuf, Vec<PathBuf>) {
        let dir = tmpdir(tag);
        let src = encrypted_file(&dir, "vorlage.pdf", 4, "", "owner");
        let files = (0..n)
            .map(|i| {
                let p = dir.join(format!("datei_{i:04}.pdf"));
                std::fs::copy(&src, &p).unwrap();
                p
            })
            .collect();
        std::fs::remove_file(src).unwrap();
        (dir, files)
    }

    /// Testumgebung: Englisch fest, Theme „Auto“, nichts wird gespeichert, kein Portal-Wächter.
    fn harness(files: Vec<PathBuf>) -> Harness<'static, App> {
        harness_with(files, Lang::En, ThemePref::Auto, [680.0, 780.0])
    }

    fn harness_with(files: Vec<PathBuf>, lang: Lang, theme: ThemePref, size: [f32; 2]) -> Harness<'static, App> {
        let settings = Settings { theme, lang: LangPref::Fixed(lang) };
        Harness::builder().with_size(size).build_eframe(move |cc| App::build(cc, files, settings, false))
    }

    /// Lässt die Oberfläche laufen, bis `cond` erfüllt ist (Worker läuft echt im Hintergrund).
    fn wait(h: &mut Harness<'static, App>, cond: impl Fn(&App) -> bool) {
        for _ in 0..3000 {
            h.step();
            if cond(h.state()) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("Zeitüberschreitung");
    }

    fn count(app: &App, f: impl Fn(&Status) -> bool) -> usize {
        app.entries.iter().filter(|e| f(&e.status)).count()
    }

    fn checked(a: &App) -> bool {
        count(a, |s| matches!(s, Status::Checking)) == 0
    }

    #[test]
    fn weiche_grenze_fragt_nach_und_begrenzt() {
        let (dir, files) = make_pdfs("limit", SOFT_LIMIT + 5);
        let mut h = harness(files);
        h.run_steps(2);
        // Dialog statt sofortigem Hinzufügen
        assert!(h.state().entries.is_empty());
        h.get_by_label(EN.many_title);
        h.get_by_label(&fill(EN.add_only, "n", SOFT_LIMIT)).click();
        h.run_steps(2);
        assert_eq!(h.state().entries.len(), SOFT_LIMIT);
        assert!(h.state().pending.is_none());

        // Prüfung läuft im Hintergrund durch
        wait(&mut h, checked);
        assert_eq!(count(h.state(), |s| matches!(s, Status::Ready(Protection::RestrictionsOnly))), SOFT_LIMIT);

        // Virtualisierte Liste: nur sichtbare Zeilen existieren im UI-Baum
        let sichtbar = h.query_all_by_label_contains("datei_").count();
        assert!(sichtbar > 0 && sichtbar < 30, "sichtbare Zeilen: {sichtbar}");

        // Alles entsperren
        h.get_by_label(&format!("🔓  {}", fill(EN.unlock_n, "n", SOFT_LIMIT))).click();
        h.run_steps(1);
        wait(&mut h, |a| a.progress.is_none());
        assert_eq!(count(h.state(), |s| matches!(s, Status::Done(..))), SOFT_LIMIT);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn dialog_abbrechen_fuegt_nichts_hinzu() {
        let (dir, files) = make_pdfs("limit-cancel", SOFT_LIMIT + 1);
        let mut h = harness(files);
        h.run_steps(2);
        h.get_by_label(EN.cancel).click();
        h.run_steps(2);
        assert!(h.state().entries.is_empty() && h.state().pending.is_none());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn abbrechen_stoppt_und_setzt_status_zurueck() {
        let (dir, files) = make_pdfs("cancel", 400);
        let mut h = harness(files);
        wait(&mut h, checked);
        h.state_mut().start();
        h.state().progress.as_ref().unwrap().cancel.store(true, Ordering::Relaxed);
        wait(&mut h, |a| a.progress.is_none());
        let a = h.state();
        let done = count(a, |s| matches!(s, Status::Done(..)));
        let ready = count(a, |s| matches!(s, Status::Ready(Protection::RestrictionsOnly)));
        assert_eq!(done + ready, 400, "keine Datei darf in Wartet/Arbeite hängen bleiben");
        assert!(ready > 0, "Abbruch hat nicht gegriffen");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn grosse_datei_wird_erst_nach_bestaetigung_geladen() {
        let dir = tmpdir("large");
        let big = dir.join("riesig.pdf");
        // Sparse-Datei: 600 MB laut Dateisystem, belegt aber keinen Platz
        std::fs::File::create(&big).unwrap().set_len(600 * 1024 * 1024).unwrap();
        let mut h = harness(vec![big]);
        wait(&mut h, |a| matches!(a.entries[0].status, Status::Large(_)));
        h.get_by_label(EN.load_anyway);
        h.get_by_label_contains(&fill(EN.st_large, "size", "600 MB"));
        assert_eq!(h.state().actionable(), 0, "große Datei darf nicht automatisch verarbeitet werden");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn passwortfeld_nur_bei_bedarf() {
        let (dir, files) = make_pdfs("pwfield", 2);
        let mut h = harness(files);
        wait(&mut h, checked);
        h.run_steps(2);
        assert!(h.query_by_label(EN.password).is_none(), "nur Einschränkungen → kein Passwortfeld");

        let locked = encrypted_file(&dir, "locked.pdf", 5, "geheim", "owner");
        h.state_mut().add_files(vec![locked]);
        wait(&mut h, checked);
        h.run_steps(2);
        h.get_by_label(EN.password);
        // Berechtigungen wurden mitgelesen
        assert!(h.state().entries.iter().all(|e| e.permissions.is_some()));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn einstellungen_theme_und_sprache() {
        let mut h = harness(vec![]);
        h.run_steps(2);
        assert_eq!(h.state().applied_dark, Some(true), "ohne System-Info: dunkel");

        h.get_by_label("⚙").click();
        h.run_steps(2);
        assert_eq!(h.state().view, View::Settings);

        h.get_by_label(EN.theme_light).click();
        h.run_steps(2);
        assert_eq!(h.state().settings.theme, ThemePref::Light);
        assert_eq!(h.state().applied_dark, Some(false));

        h.get_by_value("English").click();
        h.run_steps(2);
        h.get_by_label("Deutsch").click();
        h.run_steps(2);
        assert_eq!(h.state().lang, Lang::De);
        h.get_by_label(DE.appearance);

        h.get_by_label(&format!("⬅  {}", DE.back)).click();
        h.run_steps(2);
        assert_eq!(h.state().view, View::Main);
        h.get_by_label(DE.empty_list);
    }

    #[test]
    fn renderer_reihenfolge() {
        let r = renderers();
        assert_eq!(r.last(), Some(&eframe::Renderer::Glow), "OpenGL ist immer die letzte Rückfallebene");
        #[cfg(windows)]
        assert_eq!(r.first(), Some(&eframe::Renderer::Wgpu), "Windows versucht zuerst DirectX 12");
    }

    #[test]
    fn schutz_modus() {
        let (dir, files) = make_pdfs("protect-gui", 3);
        let mut h = harness(files);
        wait(&mut h, checked);
        h.get_by_label(&format!("🔒  {}", EN.protect)).click();
        h.run_steps(2);
        assert_eq!(h.state().mode, Mode::Protect);

        // Ohne Passwort und mit allen Rechten gibt es nichts zu schützen
        let btn = format!("🔒  {}", fill(EN.protect_n, "n", 3));
        assert!(!h.state().protect_options().is_effective());
        h.get_by_label(&btn).click();
        h.run_steps(2);
        assert!(h.state().progress.is_none(), "darf nicht starten");

        h.get_by_label(EN.allow_none).click();
        h.run_steps(2);
        h.state_mut().open_pw = "geheim".into();
        h.run_steps(2);
        h.get_by_label(&format!("🔐 {}", EN.keep_password)); // Hinweis zum Aufbewahren sichtbar
        h.get_by_label(&btn).click();
        h.run_steps(1);
        wait(&mut h, |a| a.progress.is_none());
        let outs: Vec<PathBuf> = h
            .state()
            .entries
            .iter()
            .map(|e| match &e.status {
                Status::Done(p, Mode::Protect) => p.clone(),
                s => panic!("unerwarteter Status {s:?}"),
            })
            .collect();
        for o in outs {
            assert!(o.to_string_lossy().ends_with("_protected.pdf"));
            let i = core::inspect(&o).unwrap();
            assert_eq!(i.protection, Protection::PasswordRequired);
            assert!(!i.permissions.unwrap().intersects(ALL_PERMISSIONS));
        }
        std::fs::remove_dir_all(dir).ok();
    }

    /// Kleinstes erlaubtes Fenster, längere deutsche Texte: Hauptknopf muss sichtbar bleiben,
    /// der Untertitel darf das ⚙ nicht überdecken.
    #[test]
    fn layout_bei_kleinem_fenster() {
        let (dir, files) = make_pdfs("layout", 5);
        let (w, h) = (540.0, 620.0);
        let mut hs = harness_with(files, Lang::De, ThemePref::Dark, [w, h]);
        wait(&mut hs, checked);
        for (mode, label) in [
            (Mode::Unlock, format!("🔓  {}", fill(DE.unlock_n, "n", 5))),
            (Mode::Protect, format!("🔒  {}", fill(DE.protect_n, "n", 5))),
        ] {
            hs.state_mut().mode = mode;
            hs.state_mut().open_pw = "x".into(); // Hinweiszeile im Schutz-Modus mit anzeigen
            hs.run_steps(4);
            let r = hs.get_by_label(&label).rect();
            assert!(r.top() >= 0.0 && r.bottom() <= h, "{mode:?}: Knopf außerhalb des Fensters: {r:?}");
            let gear = hs.get_by_label("⚙").rect();
            let sub = hs.get_by_label(DE.subtitle).rect();
            assert!(sub.right() <= gear.left(), "Untertitel überdeckt ⚙: {sub:?} / {gear:?}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    /// Name, Sprache, Theme, Fenstergröße, Dateien, Modus, Ansicht
    type Shot = (&'static str, Lang, ThemePref, [f32; 2], Vec<PathBuf>, Mode, View);

    /// Bildschirmfotos zur Sichtkontrolle (braucht eine Grafikkarte, daher nur auf Wunsch):
    /// `cargo test screenshots -- --ignored` → `target/screenshots/*.png`
    #[test]
    #[ignore]
    fn screenshots() {
        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/screenshots");
        std::fs::create_dir_all(&out).unwrap();
        let (dir, files) = make_pdfs("shots", 4);
        let locked = encrypted_file(&dir, "vertraulich.pdf", 5, "geheim", "owner");
        let mut all = files.clone();
        all.push(locked);

        let shots: [Shot; 6] = [
            ("de_leer_dunkel", Lang::De, ThemePref::Dark, [680.0, 780.0], vec![], Mode::Unlock, View::Main),
            ("de_entsperren_dunkel", Lang::De, ThemePref::Dark, [680.0, 780.0], all.clone(), Mode::Unlock, View::Main),
            (
                "de_schuetzen_dunkel",
                Lang::De,
                ThemePref::Dark,
                [680.0, 780.0],
                files.clone(),
                Mode::Protect,
                View::Main,
            ),
            (
                "de_schuetzen_klein_hell",
                Lang::De,
                ThemePref::Light,
                [540.0, 620.0],
                files.clone(),
                Mode::Protect,
                View::Main,
            ),
            ("en_einstellungen_hell", Lang::En, ThemePref::Light, [680.0, 780.0], vec![], Mode::Unlock, View::Settings),
            ("ru_entsperren_hell", Lang::Ru, ThemePref::Light, [680.0, 780.0], all.clone(), Mode::Unlock, View::Main),
        ];
        for (name, lang, theme, size, files, mode, view) in shots {
            let mut h = harness_with(files, lang, theme, size);
            wait(&mut h, checked);
            h.state_mut().mode = mode;
            h.state_mut().view = view;
            h.run_steps(6);
            let img = h.render().expect("Rendern fehlgeschlagen");
            img.save(out.join(format!("{name}.png"))).unwrap();
        }
        std::fs::remove_dir_all(dir).ok();
    }
}
