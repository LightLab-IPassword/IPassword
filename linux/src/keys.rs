//! Turning the settings' hotkey description (Windows-style modifier flags and virtual-key codes)
//! into X11 modifier masks, key symbols and key codes. Pure functions, unit-tested.

use ipassword_shared::config::{MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN};

pub const X_SHIFT: u16 = 0x01;
pub const X_LOCK: u16 = 0x02; // Caps Lock
pub const X_CONTROL: u16 = 0x04;
pub const X_MOD1: u16 = 0x08; // Alt
pub const X_MOD2: u16 = 0x10; // Num Lock
pub const X_MOD4: u16 = 0x40; // Super / Windows key

/// Hotkey modifier flags to an X11 modifier mask.
pub fn x_modifiers(mods: u32) -> u16 {
    let mut mask = 0;
    if mods & MOD_ALT != 0 {
        mask |= X_MOD1;
    }
    if mods & MOD_CONTROL != 0 {
        mask |= X_CONTROL;
    }
    if mods & MOD_SHIFT != 0 {
        mask |= X_SHIFT;
    }
    if mods & MOD_WIN != 0 {
        mask |= X_MOD4;
    }
    mask
}

/// Caps Lock and Num Lock shouldn't stop a hotkey from matching.
pub fn ignoring_lock_bits(state: u16) -> u16 {
    state & !(X_LOCK | X_MOD2)
}

/// Windows virtual-key code (as used by the settings) to an X11 key symbol.
pub fn keysym_from_vk(vk: u32) -> Option<u32> {
    match vk {
        0x30..=0x39 => Some(vk),               // digits: same as ASCII
        0x41..=0x5A => Some(vk + 0x20),        // letters: lowercase ASCII
        0x70..=0x87 => Some(0xFFBE + (vk - 0x70)), // F1..F24
        _ => None,
    }
}

/// The key symbols of every physical key that counts as one of the hotkey's modifiers.
pub fn modifier_keysyms(mods: u32) -> Vec<u32> {
    let mut syms = Vec::new();
    if mods & MOD_ALT != 0 {
        syms.extend([0xFFE9, 0xFFEA]); // Alt_L, Alt_R
    }
    if mods & MOD_CONTROL != 0 {
        syms.extend([0xFFE3, 0xFFE4]); // Control_L, Control_R
    }
    if mods & MOD_SHIFT != 0 {
        syms.extend([0xFFE1, 0xFFE2]); // Shift_L, Shift_R
    }
    if mods & MOD_WIN != 0 {
        syms.extend([0xFFEB, 0xFFEC]); // Super_L, Super_R
    }
    syms
}

/// Finds the key code that produces `keysym`, given the server's keyboard mapping
/// (`per` key symbols per key code, starting at key code `min`).
pub fn keycode_for(keysyms: &[u32], per: usize, min: u8, keysym: u32) -> Option<u8> {
    if per == 0 {
        return None;
    }
    keysyms
        .chunks(per)
        .position(|chunk| chunk.contains(&keysym))
        .and_then(|index| u8::try_from(usize::from(min) + index).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifier_flags_become_x11_masks() {
        assert_eq!(x_modifiers(MOD_ALT), X_MOD1);
        assert_eq!(x_modifiers(MOD_ALT | MOD_CONTROL), X_MOD1 | X_CONTROL);
        assert_eq!(x_modifiers(MOD_SHIFT | MOD_WIN), X_SHIFT | X_MOD4);
        assert_eq!(x_modifiers(0), 0);
    }

    #[test]
    fn lock_keys_are_ignored_when_matching() {
        assert_eq!(ignoring_lock_bits(X_MOD1 | X_LOCK | X_MOD2), X_MOD1);
        assert_eq!(ignoring_lock_bits(X_MOD1), X_MOD1);
    }

    #[test]
    fn virtual_keys_map_to_key_symbols() {
        assert_eq!(keysym_from_vk(0x43), Some(0x63)); // C -> 'c'
        assert_eq!(keysym_from_vk(0x56), Some(0x76)); // V -> 'v'
        assert_eq!(keysym_from_vk(0x37), Some(0x37)); // 7
        assert_eq!(keysym_from_vk(0x70), Some(0xFFBE)); // F1
        assert_eq!(keysym_from_vk(0x7B), Some(0xFFC9)); // F12
        assert_eq!(keysym_from_vk(0x20), None);
    }

    #[test]
    fn modifier_symbols_cover_both_sides_of_the_keyboard() {
        assert_eq!(modifier_keysyms(MOD_ALT), vec![0xFFE9, 0xFFEA]);
        assert_eq!(modifier_keysyms(MOD_CONTROL | MOD_SHIFT).len(), 4);
        assert!(modifier_keysyms(0).is_empty());
    }

    #[test]
    fn finds_key_codes_in_the_keyboard_mapping() {
        // Key codes 8, 9, 10 with two symbols each (unshifted, shifted).
        let mapping = [0x61, 0x41, 0x62, 0x42, 0x63, 0x43];
        assert_eq!(keycode_for(&mapping, 2, 8, 0x61), Some(8));
        assert_eq!(keycode_for(&mapping, 2, 8, 0x62), Some(9));
        assert_eq!(keycode_for(&mapping, 2, 8, 0x43), Some(10));
        assert_eq!(keycode_for(&mapping, 2, 8, 0x7A), None);
        assert_eq!(keycode_for(&mapping, 0, 8, 0x61), None);
    }
}
