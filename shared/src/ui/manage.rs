//! The main window: status, account creation, hotkeys and startup settings.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroize;

use super::common::{describe_error, field, palette, primary_button, run_app, window_options, Palette};
use crate::config::Config;
use crate::core_lib;
use crate::paths;
use crate::platform::platform;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Home,
    Account,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Job {
    Create,
    Change,
}

pub fn run() {
    // Opening the app also makes sure the background process is up.
    if !platform().daemon_running() {
        platform().start_daemon();
    }
    run_app(
        "IPassword",
        window_options("IPassword", [540.0, 660.0]),
        ManageApp::new(),
    );
}

struct ManageApp {
    pal: Palette,
    tab: Tab,
    data_dir: PathBuf,
    config: Config,
    capture_hk: String,
    paste_hk: String,
    autostart: bool,
    daemon_running: bool,
    last_poll: Instant,
    core_version: Option<String>,
    core_error: Option<String>,
    create_user: String,
    create_pw: String,
    create_pw2: String,
    change_user: String,
    change_old: String,
    change_new: String,
    change_new2: String,
    message: Option<(bool, String)>,
    pending: Option<Job>,
    pending_ready: bool,
}

impl ManageApp {
    fn new() -> Self {
        let config = Config::load(&paths::config_path());
        let (core_version, core_error) = match core_lib::core() {
            Ok(core) => (Some(core.version()), None),
            Err(message) => (None, Some(message)),
        };
        ManageApp {
            pal: palette(),
            tab: Tab::Home,
            data_dir: paths::data_dir(),
            capture_hk: config.capture_hotkey.clone(),
            paste_hk: config.paste_hotkey.clone(),
            config,
            autostart: platform().autostart_enabled(),
            daemon_running: platform().daemon_running(),
            last_poll: Instant::now(),
            core_version,
            core_error,
            create_user: String::new(),
            create_pw: String::new(),
            create_pw2: String::new(),
            change_user: String::new(),
            change_old: String::new(),
            change_new: String::new(),
            change_new2: String::new(),
            message: None,
            pending: None,
            pending_ready: false,
        }
    }

    fn ok(&mut self, text: impl Into<String>) {
        self.message = Some((false, text.into()));
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.message = Some((true, text.into()));
    }

    fn request(&mut self, job: Job) {
        self.message = None;
        let problem: Option<&str> = match job {
            Job::Create => {
                if self.create_user.trim().is_empty() {
                    Some("Enter a username.")
                } else if self.create_pw.chars().count() < 8 {
                    Some("Use a master password of at least 8 characters.")
                } else if self.create_pw != self.create_pw2 {
                    Some("The two passwords don't match.")
                } else {
                    None
                }
            }
            Job::Change => {
                if self.change_user.trim().is_empty() || self.change_old.is_empty() {
                    Some("Enter your username and current master password.")
                } else if self.change_new.chars().count() < 8 {
                    Some("Use a new master password of at least 8 characters.")
                } else if self.change_new != self.change_new2 {
                    Some("The two new passwords don't match.")
                } else {
                    None
                }
            }
        };
        match problem {
            Some(text) => self.fail(text),
            None => {
                self.pending = Some(job);
                self.pending_ready = false;
            }
        }
    }

    /// Runs after a "Working..." frame has been shown (key derivation is deliberately slow).
    fn run_job(&mut self, job: Job) {
        let core = match core_lib::core() {
            Ok(core) => core,
            Err(message) => {
                self.fail(message);
                return;
            }
        };
        match job {
            Job::Create => {
                match core.create_user(&self.data_dir, self.create_user.trim(), &self.create_pw) {
                    Ok(()) => {
                        let who = self.create_user.trim().to_string();
                        let hotkey = self.config.capture_hotkey.clone();
                        self.ok(format!(
                            "Account \"{who}\" created. Select a password in any app and press {hotkey} to save it."
                        ));
                        self.create_user.clear();
                        self.create_pw.zeroize();
                        self.create_pw2.zeroize();
                    }
                    Err(e) => self.fail(describe_error(&e)),
                }
            }
            Job::Change => {
                match core.change_password(
                    &self.data_dir,
                    self.change_user.trim(),
                    &self.change_old,
                    &self.change_new,
                ) {
                    Ok(()) => {
                        self.ok("Master password changed.");
                        self.change_user.clear();
                        self.change_old.zeroize();
                        self.change_new.zeroize();
                        self.change_new2.zeroize();
                    }
                    Err(e) => self.fail(describe_error(&e)),
                }
            }
        }
    }

    fn save_hotkeys(&mut self) {
        let mut config = self.config.clone();
        config.capture_hotkey = self.capture_hk.trim().to_string();
        config.paste_hotkey = self.paste_hk.trim().to_string();
        if let Err(e) = config.hotkeys() {
            self.fail(e);
            return;
        }
        if let Err(e) = config.save(&paths::config_write_path()) {
            self.fail(format!("Couldn't save config.json: {e}"));
            return;
        }
        self.config = config;
        platform().restart_daemon();
        self.daemon_running = platform().daemon_running();
        self.ok("Hotkeys saved. The background process was restarted.");
    }

    fn draw_message(&self, ui: &mut egui::Ui) {
        if self.pending.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(egui::RichText::new("Working...").color(self.pal.muted));
            });
        }
        if let Some((is_error, text)) = &self.message {
            let color = if *is_error { self.pal.danger } else { self.pal.ok };
            ui.colored_label(color, text.as_str());
        }
    }

    fn draw_header(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("IPassword");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.daemon_running {
                    ui.colored_label(pal.ok, "Running in the background");
                } else {
                    ui.colored_label(pal.danger, "Not running");
                }
            });
        });
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Home, "Home");
            ui.selectable_value(&mut self.tab, Tab::Account, "Account");
            ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
        });
        ui.add_space(4.0);
    }

    fn draw_home(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        if let Some(error) = &self.core_error {
            ui.colored_label(pal.danger, error.as_str());
            ui.add_space(6.0);
        }

        ui.label(egui::RichText::new("How it works").strong().size(17.0));
        ui.label(format!(
            "1. Select a password in any app and press {} to save it.",
            self.config.capture_hotkey
        ));
        ui.label(format!(
            "2. Click into a login box and press {} to paste a saved one.",
            self.config.paste_hotkey
        ));
        ui.label(format!(
            "3. Need a new password? Press {} and use \"Generate a new password\".",
            self.config.paste_hotkey
        ));
        ui.label(
            egui::RichText::new("Everything stays encrypted on this computer. Nothing is sent anywhere.")
                .color(pal.muted),
        );
        ui.add_space(6.0);
        ui.label(
            egui::RichText::new("New here? Create an account on the Account tab first.")
                .color(pal.muted),
        );

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if self.daemon_running {
                if ui.button("Quit background process").clicked() {
                    platform().stop_daemon();
                    self.daemon_running = false;
                }
            } else if ui.button("Start background process").clicked() {
                platform().start_daemon();
            }
            if ui.button("Open data folder").clicked() {
                platform().open_folder(&self.data_dir);
            }
        });

        ui.add_space(10.0);
        let mode = if paths::is_portable() { " (portable)" } else { "" };
        ui.label(
            egui::RichText::new(format!("Data folder: {}{mode}", self.data_dir.display()))
                .color(pal.muted)
                .small(),
        );
        if let Some(version) = &self.core_version {
            ui.label(
                egui::RichText::new(format!("Core library {version}"))
                    .color(pal.muted)
                    .small(),
            );
        }
    }

    fn draw_account(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        let working = self.pending.is_some();

        ui.label(egui::RichText::new("Create account").strong().size(17.0));
        ui.label(
            egui::RichText::new(
                "A forgotten master password can't be recovered. Pick a long one you'll remember.",
            )
            .color(pal.muted),
        );
        ui.add_enabled_ui(!working, |ui| {
            field(ui, &pal, "IPassword username", &mut self.create_user, false);
            field(ui, &pal, "Master password (8+ characters)", &mut self.create_pw, true);
            field(ui, &pal, "Repeat master password", &mut self.create_pw2, true);
        });
        if primary_button(ui, &pal, "Create account", !working).clicked() {
            self.request(Job::Create);
        }

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(4.0);

        ui.label(egui::RichText::new("Change master password").strong().size(17.0));
        ui.add_enabled_ui(!working, |ui| {
            field(ui, &pal, "IPassword username", &mut self.change_user, false);
            field(ui, &pal, "Current master password", &mut self.change_old, true);
            field(ui, &pal, "New master password (8+ characters)", &mut self.change_new, true);
            field(ui, &pal, "Repeat new master password", &mut self.change_new2, true);
        });
        if primary_button(ui, &pal, "Change password", !working).clicked() {
            self.request(Job::Change);
        }

        ui.add_space(8.0);
        self.draw_message(ui);
    }

    fn draw_settings(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;

        ui.label(egui::RichText::new("Hotkeys").strong().size(17.0));
        ui.label(
            egui::RichText::new("For example Alt+C, Ctrl+Shift+K or Win+F5. Needs at least one modifier.")
                .color(pal.muted),
        );
        field(ui, &pal, "Save the selected text", &mut self.capture_hk, false);
        field(ui, &pal, "Paste a saved password", &mut self.paste_hk, false);
        if primary_button(ui, &pal, "Save hotkeys", true).clicked() {
            self.save_hotkeys();
        }

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(4.0);

        ui.label(egui::RichText::new("Startup").strong().size(17.0));
        if ui
            .checkbox(&mut self.autostart, "Start IPassword when I sign in")
            .changed()
        {
            if let Err(e) = platform().set_autostart(self.autostart) {
                self.autostart = !self.autostart;
                self.fail(e);
            }
        }

        ui.add_space(12.0);
        ui.separator();
        ui.add_space(4.0);

        ui.label(egui::RichText::new("Make it yours").strong().size(17.0));
        ui.label(
            egui::RichText::new(
                "config.json (hotkeys, timeouts, data folder, pinned core hash) and theme.json (colors, \
corner radius, font size) can be edited with any text editor. Restart IPassword afterwards.",
            )
            .color(pal.muted),
        );
        if ui.button("Open program folder").clicked() {
            platform().open_folder(&paths::exe_dir());
        }

        ui.add_space(8.0);
        self.draw_message(ui);
    }
}

impl eframe::App for ManageApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_secs(1));
        if self.last_poll.elapsed() >= Duration::from_secs(1) {
            self.daemon_running = platform().daemon_running();
            self.last_poll = Instant::now();
        }

        if let Some(job) = self.pending {
            if !self.pending_ready {
                self.pending_ready = true;
                ctx.request_repaint();
            } else {
                self.pending = None;
                self.pending_ready = false;
                self.run_job(job);
            }
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| self.draw_header(ui));
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match self.tab {
                Tab::Home => self.draw_home(ui),
                Tab::Account => self.draw_account(ui),
                Tab::Settings => self.draw_settings(ui),
            });
        });
    }
}

impl Drop for ManageApp {
    fn drop(&mut self) {
        self.create_pw.zeroize();
        self.create_pw2.zeroize();
        self.change_old.zeroize();
        self.change_new.zeroize();
        self.change_new2.zeroize();
    }
}
