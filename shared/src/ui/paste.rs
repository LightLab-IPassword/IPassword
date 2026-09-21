//! The "paste a password" window (paste hotkey). Sign in, name the app, then either click what you
//! want typed, or generate a brand-new password (which is saved first, then typed the same way).
//! Nothing is typed until this window has closed and focus is back where you came from.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroize;

use super::common::{
    describe_error, enter_pressed, field, load_core, palette, popup_options, primary_button, run_app,
    status_line, Palette,
};
use crate::config::Config;
use crate::core_lib::{Vault, GEN_AVOID_AMBIGUOUS, GEN_DIGITS, GEN_LOWER, GEN_SYMBOLS, GEN_UPPER};
use crate::paths;
use crate::platform::{platform, TypeJob};
use crate::records::RecordData;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    Requested,
    Working,
}

#[derive(Clone, Copy)]
enum Kind {
    Password,
    Username,
    Both,
}

enum Action {
    Type(usize, Kind),
    AskDelete(usize),
    CancelDelete,
    DoDelete(usize),
}

pub fn run(target: usize) {
    if load_core().is_none() {
        return;
    }
    let outcome: Arc<Mutex<Option<TypeJob>>> = Arc::new(Mutex::new(None));
    let title = "IPassword - paste password";
    run_app(
        title,
        popup_options(title, [480.0, 680.0]),
        PasteApp::new(Arc::clone(&outcome)),
    );

    // The window is gone by now; type into the window the user came from.
    let job = outcome.lock().ok().and_then(|mut slot| slot.take());
    if let Some(job) = job {
        platform().deliver(target, &job);
    }
}

struct PasteApp {
    pal: Palette,
    idle_locked: Duration,
    idle_unlocked: Duration,
    paste_hotkey: String,
    user: String,
    master: String,
    app: String,
    vault: Option<Vault>,
    record: Option<RecordData>,
    error: Option<String>,
    /// A muted hint, e.g. "nothing saved for this app yet".
    info: Option<String>,
    /// Shown in green after a password was generated and saved.
    notice: Option<String>,
    stage: Stage,
    confirm_delete: Option<usize>,
    outcome: Arc<Mutex<Option<TypeJob>>>,
    first_frame: bool,
    focused_once: bool,
    last_activity: Instant,
    gen_account: String,
    gen_length: u32,
    gen_symbols: bool,
    gen_avoid: bool,
    new_index: Option<usize>,
}

impl PasteApp {
    fn new(outcome: Arc<Mutex<Option<TypeJob>>>) -> Self {
        let config = Config::load(&paths::config_path());
        PasteApp {
            pal: palette(),
            idle_locked: Duration::from_secs(config.idle_seconds.max(10)),
            idle_unlocked: Duration::from_secs(config.paste_idle_seconds.max(5)),
            paste_hotkey: config.paste_hotkey.clone(),
            user: String::new(),
            master: String::new(),
            app: String::new(),
            vault: None,
            record: None,
            error: None,
            info: None,
            notice: None,
            stage: Stage::Idle,
            confirm_delete: None,
            outcome,
            first_frame: true,
            focused_once: false,
            last_activity: Instant::now(),
            gen_account: String::new(),
            gen_length: 20,
            gen_symbols: true,
            gen_avoid: false,
            new_index: None,
        }
    }

    fn request(&mut self) {
        if self.stage != Stage::Idle {
            return;
        }
        self.error = None;
        let problem = if self.vault.is_none() && self.user.trim().is_empty() {
            Some("Enter your IPassword username.")
        } else if self.vault.is_none() && self.master.is_empty() {
            Some("Enter your master password.")
        } else if self.app.trim().is_empty() {
            Some("Enter which app you want.")
        } else {
            None
        };
        match problem {
            Some(text) => self.error = Some(text.to_string()),
            None => self.stage = Stage::Requested,
        }
    }

    /// Runs after the "Unlocking..." frame has been shown.
    fn run_pending(&mut self) {
        if self.vault.is_none() {
            let Some(core) = load_core() else {
                self.error = Some("The core library could not be loaded.".to_string());
                return;
            };
            match core.unlock(&paths::data_dir(), self.user.trim(), &self.master) {
                Ok(vault) => {
                    self.vault = Some(vault);
                    self.master.zeroize();
                }
                Err(e) => {
                    self.error = Some(describe_error(&e));
                    return;
                }
            }
        }
        self.lookup();
    }

    fn lookup(&mut self) {
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        self.info = None;
        self.notice = None;
        self.new_index = None;
        match vault.get_app(&self.app) {
            Ok(Some(record)) if !record.entries.is_empty() => {
                self.record = Some(record);
                self.error = None;
            }
            Ok(_) => {
                self.info = Some(format!(
                    "Nothing is saved for \"{}\" yet. Generate a password below, or try another app name.",
                    self.app.trim()
                ));
            }
            Err(e) => self.error = Some(describe_error(&e)),
        }
    }

    /// Makes a new random password, saves it under this app, then shows the list so it can be
    /// typed with the usual buttons. The password is saved *before* anything is typed, so a
    /// password that was set on a site can never be lost.
    fn generate(&mut self) {
        self.error = None;
        if self.app.trim().is_empty() {
            self.error = Some("Enter which app this password is for.".to_string());
            return;
        }
        let Some(core) = load_core() else {
            return;
        };
        let mut flags = GEN_LOWER | GEN_UPPER | GEN_DIGITS;
        if self.gen_symbols {
            flags |= GEN_SYMBOLS;
        }
        if self.gen_avoid {
            flags |= GEN_AVOID_AMBIGUOUS;
        }
        let password = match core.generate_password(self.gen_length, flags) {
            Ok(password) => password,
            Err(e) => {
                self.error = Some(describe_error(&e));
                return;
            }
        };
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        if let Err(e) = vault.add_entry(&self.app, self.gen_account.trim(), password.as_str()) {
            self.error = Some(describe_error(&e));
            return;
        }
        match vault.get_app(&self.app) {
            Ok(Some(record)) => {
                let newest = record.entries.len().checked_sub(1);
                self.record = Some(record);
                self.new_index = newest;
                self.confirm_delete = None;
                self.info = None;
                self.notice = Some(format!(
                    "Saved a new password for {}. Click Password to type it. For a confirm box, click into it and press {} again.",
                    self.app.trim(),
                    self.paste_hotkey
                ));
            }
            Ok(None) => {
                self.error = Some("Saved, but the list couldn't be reloaded.".to_string());
            }
            Err(e) => self.error = Some(describe_error(&e)),
        }
    }

    fn apply(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::Type(index, kind) => {
                let Some(record) = &self.record else {
                    return;
                };
                let Some(entry) = record.entries.get(index) else {
                    return;
                };
                let job = match kind {
                    Kind::Password => TypeJob {
                        username: None,
                        password: Some(entry.secret.clone()),
                    },
                    Kind::Username => TypeJob {
                        username: Some(entry.username.clone()),
                        password: None,
                    },
                    Kind::Both => TypeJob {
                        username: Some(entry.username.clone()),
                        password: Some(entry.secret.clone()),
                    },
                };
                if let Ok(mut slot) = self.outcome.lock() {
                    *slot = Some(job);
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Action::AskDelete(index) => self.confirm_delete = Some(index),
            Action::CancelDelete => self.confirm_delete = None,
            Action::DoDelete(index) => self.delete(index, ctx),
        }
    }

    fn delete(&mut self, index: usize, ctx: &egui::Context) {
        self.confirm_delete = None;
        self.new_index = None;
        self.notice = None;
        let Some(entry_id) = self
            .record
            .as_ref()
            .and_then(|r| r.entries.get(index))
            .map(|e| e.id.clone())
        else {
            return;
        };
        let Some(vault) = self.vault.as_ref() else {
            return;
        };
        if let Err(e) = vault.remove_entry(&self.app, &entry_id) {
            self.error = Some(describe_error(&e));
            return;
        }
        match vault.get_app(&self.app) {
            Ok(Some(record)) if !record.entries.is_empty() => self.record = Some(record),
            _ => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        }
    }

    fn draw_login(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        ui.heading("Paste password");
        ui.label(egui::RichText::new("Sign in, then pick the app.").color(pal.muted));
        ui.add_space(2.0);

        let working = self.stage != Stage::Idle;
        let focus_first = std::mem::take(&mut self.first_frame);
        let mut submit = false;
        ui.add_enabled_ui(!working, |ui| {
            let r = field(ui, &pal, "IPassword username", &mut self.user, false);
            if focus_first {
                r.request_focus();
            }
            submit |= enter_pressed(ui, &r);
            let r = field(ui, &pal, "Master password", &mut self.master, true);
            submit |= enter_pressed(ui, &r);
            let r = field(ui, &pal, "App (for example: netflix)", &mut self.app, false);
            submit |= enter_pressed(ui, &r);
        });
        ui.add_space(4.0);
        status_line(ui, &pal, working, &self.error);
        if primary_button(ui, &pal, "Unlock", !working).clicked() || submit {
            self.request();
        }
    }

    /// The options and button for making a new password. Returns true when the button was clicked.
    fn draw_generate(&mut self, ui: &mut egui::Ui) -> bool {
        let pal = self.pal;
        ui.add_space(6.0);
        ui.separator();
        ui.label(egui::RichText::new("Generate a new password").strong().size(16.0));
        ui.label(
            egui::RichText::new("It is saved for this app first, then you type it with the buttons above.")
                .color(pal.muted)
                .small(),
        );
        field(
            ui,
            &pal,
            "Account username or email (optional)",
            &mut self.gen_account,
            false,
        );
        ui.horizontal(|ui| {
            ui.label("Length");
            ui.add(egui::Slider::new(&mut self.gen_length, 8..=64));
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.gen_symbols, "Symbols");
            ui.checkbox(&mut self.gen_avoid, "Avoid look-alikes (0/O, 1/l)");
        });
        primary_button(ui, &pal, "Generate and save", true).clicked()
    }

    /// Signed in, but the app name didn't match anything saved.
    fn draw_lookup(&mut self, ui: &mut egui::Ui) -> bool {
        let pal = self.pal;
        ui.heading("Unlocked");
        if let Some(info) = &self.info {
            ui.label(egui::RichText::new(info.as_str()).color(pal.muted));
        }
        ui.add_space(2.0);

        let working = self.stage != Stage::Idle;
        let mut submit = false;
        ui.add_enabled_ui(!working, |ui| {
            let r = field(ui, &pal, "App (for example: netflix)", &mut self.app, false);
            submit |= enter_pressed(ui, &r);
        });
        ui.add_space(4.0);
        status_line(ui, &pal, working, &self.error);
        if primary_button(ui, &pal, "Find saved logins", !working).clicked() || submit {
            self.request();
        }
        self.draw_generate(ui)
    }

    fn draw_pick(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> bool {
        let pal = self.pal;
        let mut action: Option<Action> = None;
        if let Some(record) = &self.record {
            ui.heading(record.display_name.as_str());
            if let Some(notice) = &self.notice {
                ui.colored_label(pal.ok, notice.as_str());
            } else {
                ui.label(
                    egui::RichText::new("Click what to type into the window you came from.")
                        .color(pal.muted),
                );
            }
            if let Some(message) = &self.error {
                ui.colored_label(pal.danger, message);
            }
            ui.add_space(2.0);

            egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                for (index, entry) in record.entries.iter().enumerate() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        let name = if entry.username.is_empty() {
                            "(no username)"
                        } else {
                            entry.username.as_str()
                        };
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(name).strong());
                            if self.new_index == Some(index) {
                                ui.label(egui::RichText::new("new").color(pal.ok).small());
                            }
                        });
                        if let Some(note) = &entry.note {
                            ui.label(egui::RichText::new(note.as_str()).color(pal.muted).small());
                        }
                        if self.confirm_delete == Some(index) {
                            ui.horizontal(|ui| {
                                ui.colored_label(pal.danger, "Delete this login?");
                                if ui.button("Yes, delete").clicked() {
                                    action = Some(Action::DoDelete(index));
                                }
                                if ui.button("Cancel").clicked() {
                                    action = Some(Action::CancelDelete);
                                }
                            });
                        } else {
                            ui.horizontal(|ui| {
                                let main = egui::Button::new(
                                    egui::RichText::new("Password").strong().color(pal.accent_text),
                                )
                                .fill(pal.accent);
                                if ui.add(main).clicked() {
                                    action = Some(Action::Type(index, Kind::Password));
                                }
                                if ui.button("Username").clicked() {
                                    action = Some(Action::Type(index, Kind::Username));
                                }
                                if ui.button("User + Pass").clicked() {
                                    action = Some(Action::Type(index, Kind::Both));
                                }
                                if ui.button("Delete").clicked() {
                                    action = Some(Action::AskDelete(index));
                                }
                            });
                        }
                    });
                    ui.add_space(2.0);
                }
            });
        }
        let generate = self.draw_generate(ui);
        if let Some(action) = action {
            self.apply(action, ctx);
            return false;
        }
        generate
    }
}

impl eframe::App for PasteApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.focused_once {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            self.focused_once = true;
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if ctx.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }
        let limit = if self.vault.is_some() {
            self.idle_unlocked
        } else {
            self.idle_locked
        };
        if self.last_activity.elapsed() > limit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_secs(1));

        match self.stage {
            Stage::Requested => {
                self.stage = Stage::Working;
                ctx.request_repaint();
            }
            Stage::Working => {
                self.run_pending();
                self.stage = Stage::Idle;
            }
            Stage::Idle => {}
        }

        let mut generate = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.record.is_some() {
                generate = self.draw_pick(ui, ctx);
            } else if self.vault.is_some() {
                generate = self.draw_lookup(ui);
            } else {
                self.draw_login(ui);
            }
        });
        if generate {
            self.generate();
        }
    }
}

impl Drop for PasteApp {
    fn drop(&mut self) {
        self.master.zeroize();
    }
}
