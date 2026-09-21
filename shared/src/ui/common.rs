//! Shared look and helpers for all IPassword windows. Colors come from theme.json.

use eframe::egui::{self, Color32};

use crate::core_lib::{self, CoreError};
use crate::paths;
use crate::platform::platform;
use crate::theme::{parse_hex, Theme};

/// The few colors the windows use directly (everything else is applied to egui's visuals).
#[derive(Clone, Copy)]
pub struct Palette {
    pub accent: Color32,
    pub accent_text: Color32,
    pub danger: Color32,
    pub ok: Color32,
    pub muted: Color32,
}

fn color(value: &str, fallback: &str) -> Color32 {
    let [r, g, b] = parse_hex(value)
        .or_else(|| parse_hex(fallback))
        .unwrap_or([128, 128, 128]);
    Color32::from_rgb(r, g, b)
}

pub fn palette() -> Palette {
    let t = Theme::load(&paths::theme_path());
    let d = Theme::default();
    Palette {
        accent: color(&t.accent, &d.accent),
        accent_text: color(&t.accent_text, &d.accent_text),
        danger: color(&t.danger, &d.danger),
        ok: color(&t.ok, &d.ok),
        muted: color(&t.muted, &d.muted),
    }
}

pub fn apply_theme(ctx: &egui::Context) {
    let t = Theme::load(&paths::theme_path());
    let d = Theme::default();

    let accent = color(&t.accent, &d.accent);
    let button = color(&t.button, &d.button);
    let button_hover = color(&t.button_hover, &d.button_hover);
    let rounding = egui::Rounding::same(t.rounding.clamp(0.0, 24.0));

    let mut v = egui::Visuals::dark();
    v.panel_fill = color(&t.background, &d.background);
    v.window_fill = color(&t.panel, &d.panel);
    v.faint_bg_color = color(&t.panel, &d.panel);
    v.extreme_bg_color = color(&t.input, &d.input);
    v.override_text_color = Some(color(&t.text, &d.text));
    v.hyperlink_color = accent;
    v.selection.bg_fill = accent.gamma_multiply(0.45);
    v.selection.stroke = egui::Stroke::new(1.0, accent);
    v.window_rounding = rounding;
    v.menu_rounding = rounding;

    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, button);
    v.widgets.inactive.bg_fill = button;
    v.widgets.inactive.weak_bg_fill = button;
    v.widgets.hovered.bg_fill = button_hover;
    v.widgets.hovered.weak_bg_fill = button_hover;
    v.widgets.active.bg_fill = accent;
    v.widgets.active.weak_bg_fill = accent;
    for widget in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        widget.rounding = rounding;
    }
    ctx.set_visuals(v);

    let base = t.font_size.clamp(10.0, 28.0);
    let spacing = t.spacing.clamp(2.0, 20.0);
    ctx.style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(spacing, spacing);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.interact_size.y = 32.0;
        style
            .text_styles
            .insert(egui::TextStyle::Heading, egui::FontId::proportional(base + 6.0));
        style
            .text_styles
            .insert(egui::TextStyle::Body, egui::FontId::proportional(base));
        style
            .text_styles
            .insert(egui::TextStyle::Button, egui::FontId::proportional(base));
        style
            .text_styles
            .insert(egui::TextStyle::Small, egui::FontId::proportional(base - 3.0));
        style
            .text_styles
            .insert(egui::TextStyle::Monospace, egui::FontId::monospace(base));
    });
}

/// A small pop-up window that appears on top of everything (the save / paste windows).
pub fn popup_options(title: &str, size: [f32; 2]) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(size)
            .with_resizable(false)
            .with_always_on_top(),
        centered: true,
        ..Default::default()
    }
}

/// The normal main window.
pub fn window_options(title: &str, size: [f32; 2]) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size(size)
            .with_min_inner_size([420.0, 480.0]),
        centered: true,
        ..Default::default()
    }
}

pub fn run_app<A: eframe::App + 'static>(title: &str, options: eframe::NativeOptions, app: A) {
    let result = eframe::run_native(
        title,
        options,
        Box::new(move |cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    );
    if let Err(e) = result {
        platform().message_box("IPassword", &format!("Couldn't open the window: {e}"), true);
    }
}

/// A small muted label above a text box.
pub fn field(
    ui: &mut egui::Ui,
    pal: &Palette,
    label: &str,
    text: &mut String,
    password: bool,
) -> egui::Response {
    ui.label(egui::RichText::new(label).color(pal.muted).small());
    ui.add(
        egui::TextEdit::singleline(text)
            .password(password)
            .desired_width(f32::INFINITY),
    )
}

pub fn enter_pressed(ui: &egui::Ui, response: &egui::Response) -> bool {
    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// The main call-to-action: a full-width accent-colored button.
pub fn primary_button(ui: &mut egui::Ui, pal: &Palette, label: &str, enabled: bool) -> egui::Response {
    let width = ui.available_width();
    ui.add_enabled(
        enabled,
        egui::Button::new(egui::RichText::new(label).strong().color(pal.accent_text))
            .fill(pal.accent)
            .min_size(egui::vec2(width, 38.0)),
    )
}

/// "Unlocking..." line and any error text.
pub fn status_line(ui: &mut egui::Ui, pal: &Palette, working: bool, error: &Option<String>) {
    if working {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(egui::RichText::new("Unlocking...").color(pal.muted));
        });
    }
    if let Some(message) = error {
        ui.colored_label(pal.danger, message);
    }
}

/// Loads the core library or shows why it couldn't be loaded.
pub fn load_core() -> Option<&'static core_lib::Core> {
    match core_lib::core() {
        Ok(core) => Some(core),
        Err(message) => {
            platform().message_box("IPassword", &message, true);
            None
        }
    }
}

pub fn describe_error(e: &CoreError) -> String {
    match e.code {
        core_lib::WRONG_PASSWORD => "Wrong master password.".to_string(),
        core_lib::USER_NOT_FOUND => {
            "No such user. Create an account in the IPassword window first.".to_string()
        }
        core_lib::USER_EXISTS => "That username already exists.".to_string(),
        core_lib::CORRUPT => "A vault file looks damaged or tampered with.".to_string(),
        _ if e.message.is_empty() => "Something went wrong.".to_string(),
        _ => e.message.clone(),
    }
}
