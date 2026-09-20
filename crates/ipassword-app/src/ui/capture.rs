//! The "save a password" window (Alt+C). The daemon captures the selected text and pipes it in
//! on stdin; this window asks who you are and which app it belongs to, then saves it.

use std::io::Read;
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroize;

use super::common::{
    describe_error, enter_pressed, field, load_core, palette, popup_options, primary_button, run_app,
    status_line, Palette,
};
use crate::config::Config;
use crate::paths;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Idle,
    Requested,
    Working,
}

pub fn run(_target: usize) {
    let mut secret = String::new();
    let _ = std::io::stdin().read_to_string(&mut secret);
    while secret.ends_with('\n') || secret.ends_with('\r') {
        secret.pop();
    }
    if load_core().is_none() {
        secret.zeroize();
        return;
    }
    let title = "IPassword - save password";
    run_app(title, popup_options(title, [460.0, 540.0]), CaptureApp::new(secret));
}

struct CaptureApp {
    pal: Palette,
    idle_limit: Duration,
    user: String,
    master: String,
    app: String,
    account: String,
    secret: String,
    had_capture: bool,
    show_secret: bool,
    error: Option<String>,
    stage: Stage,
    saved: Option<(Instant, String)>,
    first_frame: bool,
    focused_once: bool,
    last_activity: Instant,
}

impl CaptureApp {
    fn new(secret: String) -> Self {
        let config = Config::load(&paths::config_path());
        CaptureApp {
            pal: palette(),
            idle_limit: Duration::from_secs(config.idle_seconds.max(10)),
            user: String::new(),
            master: String::new(),
            app: String::new(),
            account: String::new(),
            had_capture: !secret.is_empty(),
            secret,
            show_secret: false,
            error: None,
            stage: Stage::Idle,
            saved: None,
            first_frame: true,
            focused_once: false,
            last_activity: Instant::now(),
        }
    }

    fn request_save(&mut self) {
        if self.stage != Stage::Idle {
            return;
        }
        self.error = None;
        let problem = if self.user.trim().is_empty() {
            Some("Enter your IPassword username.")
        } else if self.master.is_empty() {
            Some("Enter your master password.")
        } else if self.app.trim().is_empty() {
            Some("Enter which app this password is for.")
        } else if self.secret.is_empty() {
            Some("There's no password to save.")
        } else {
            None
        };
        match problem {
            Some(text) => self.error = Some(text.to_string()),
            None => self.stage = Stage::Requested,
        }
    }

    fn save(&mut self) {
        let Some(core) = load_core() else {
            self.error = Some("The core library could not be loaded.".to_string());
            return;
        };
        let vault = match core.unlock(&paths::data_dir(), self.user.trim(), &self.master) {
            Ok(vault) => vault,
            Err(e) => {
                self.error = Some(describe_error(&e));
                return;
            }
        };

        // If this account already has a login for the app, update it instead of adding a duplicate.
        let account = self.account.trim().to_string();
        let existing_id: Option<String> = match vault.get_app(&self.app) {
            Ok(record) => record.and_then(|r| {
                r.entries
                    .iter()
                    .find(|e| !account.is_empty() && e.username == account)
                    .map(|e| e.id.clone())
            }),
            Err(e) => {
                self.error = Some(describe_error(&e));
                return;
            }
        };

        let (result, verb) = match &existing_id {
            Some(id) => (vault.update_secret(&self.app, id, &self.secret), "Updated"),
            None => (vault.add_entry(&self.app, &account, &self.secret), "Saved"),
        };
        match result {
            Ok(()) => {
                let message = format!("{verb} password for {}", self.app.trim());
                self.saved = Some((Instant::now(), message));
                self.master.zeroize();
                self.secret.zeroize();
            }
            Err(e) => self.error = Some(describe_error(&e)),
        }
    }

    fn draw(&mut self, ui: &mut egui::Ui) {
        let pal = self.pal;
        ui.heading("Save password");

        if let Some((_, message)) = &self.saved {
            ui.add_space(28.0);
            ui.vertical_centered(|ui| {
                ui.colored_label(pal.ok, egui::RichText::new(message.as_str()).size(18.0));
            });
            return;
        }

        let hint = if self.had_capture {
            "The selected text is ready to save."
        } else {
            "Nothing was selected. Type or paste the password below."
        };
        ui.label(egui::RichText::new(hint).color(pal.muted));
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
            let r = field(
                ui,
                &pal,
                "Account username or email (optional)",
                &mut self.account,
                false,
            );
            submit |= enter_pressed(ui, &r);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Password to save").color(pal.muted).small());
                ui.checkbox(&mut self.show_secret, "show");
            });
            let hide = !self.show_secret;
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.secret)
                    .password(hide)
                    .desired_width(f32::INFINITY),
            );
            submit |= enter_pressed(ui, &r);
        });

        ui.add_space(4.0);
        status_line(ui, &pal, working, &self.error);
        if primary_button(ui, &pal, "Save password", !working).clicked() || submit {
            self.request_save();
        }
    }
}

impl eframe::App for CaptureApp {
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
        if self.last_activity.elapsed() > self.idle_limit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if let Some((at, _)) = &self.saved {
            if at.elapsed() > Duration::from_millis(1000) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        ctx.request_repaint_after(Duration::from_millis(250));

        // The "Unlocking..." label is drawn for one frame before the slow key derivation runs.
        match self.stage {
            Stage::Requested => {
                self.stage = Stage::Working;
                ctx.request_repaint();
            }
            Stage::Working => {
                self.save();
                self.stage = Stage::Idle;
            }
            Stage::Idle => {}
        }

        egui::CentralPanel::default().show(ctx, |ui| self.draw(ui));
    }
}

impl Drop for CaptureApp {
    fn drop(&mut self) {
        self.master.zeroize();
        self.secret.zeroize();
    }
}
