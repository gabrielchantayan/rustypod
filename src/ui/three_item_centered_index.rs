//! Query the selected carousel item's exact horizontal center.

/// `ui_three_item_centered_index` — `FUN_08144cf8` at `0x08144cf8`.
/// True extent: 100 bytes (`0x08144cf8..0x08144d5c`, next function's push).
/// Raw ARM words verify two inbound plain BLs (at `0x08145600` and
/// `0x08145fec`), zero predicated inbound BLs, and zero outgoing BLs.
///
/// Read the selected slot byte at +0xa4. Slots 1, 2, and 3 return their
/// index only if their horizontal word at +0x50, +0x54, or +0x58 equals
/// 160. Invalid selectors and all other coordinates return zero without
/// changing the owner. Deliberate deviations: none in behavior; Rust uses
/// a checked selector followed by one indexed word load instead of three
/// separate conditional paths.
///
/// # Safety
/// `owner` must have a readable byte at +0xa4 and, for selectors 1..=3,
/// a readable naturally aligned u32 at +0x4c + selector*4. No null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_three_item_centered_index(owner: *const u8) -> u32 {
    let selected = owner.add(0xa4).read();
    if selected < 1 || selected > 3 {
        return 0;
    }
    let horizontal = owner.cast::<u32>().add(0x4c / 4 + selected as usize).read();
    if horizontal == 160 { selected as u32 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_slot_requires_exact_center_without_modifying_owner() {
        for selected in 1..=3u8 {
            for horizontal in [0, 159, 160, 161, u32::MAX, 0x8000_0000] {
                let mut owner = [0xcccc_ccccu32; 42];
                // Nonselected slots deliberately remain centered.
                owner[0x50 / 4..=0x58 / 4].fill(160);
                owner[0x4c / 4 + selected as usize] = horizontal;
                unsafe { owner.as_mut_ptr().cast::<u8>().add(0xa4).write(selected); }
                let before = owner;
                let result = unsafe { ui_three_item_centered_index(owner.as_ptr().cast()) };
                assert_eq!(result, if horizontal == 160 { selected as u32 } else { 0 });
                assert_eq!(owner, before);
            }
        }
    }

    #[test]
    fn every_invalid_selector_returns_zero_even_when_all_slots_are_centered() {
        let mut owner = [160u32; 42];
        for selected in 0..=u8::MAX {
            if (1..=3).contains(&selected) { continue; }
            unsafe { owner.as_mut_ptr().cast::<u8>().add(0xa4).write(selected); }
            assert_eq!(unsafe { ui_three_item_centered_index(owner.as_ptr().cast()) }, 0);
        }
    }
}
