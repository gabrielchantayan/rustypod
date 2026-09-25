//! navigation_mode_from_state — original: `FUN_08054acc` @ `0x08054acc`
//! (48 bytes; the next real function starts at `0x08054afc`).
//!
//! Raw ARM: `ldr r0,[r0,#0xf00]; ldr r0,[r0,#0x18]; cmp r0,#0; beq ...;
//! cmp r0,#1; moveq r0,#2; bxeq lr; cmp r0,#2; moveq r0,#1; bxeq lr;
//! mov r0,#0; bx lr`. Raw decoding verifies three inbound plain `bl` call
//! sites (two at `0x08172c6c`, one at `0x0817d694`), zero predicated inbound
//! `bl` calls, and zero outbound calls. It maps the nested state word 1 to
//! navigation mode 2, word 2 to navigation mode 1, and every other value to
//! mode 0. The target-width pointer field at owner+0xf00 remains a `u32`;
//! host tests use a low-address mapping rather than a host-width struct.
//! Deliberate deviations: none in behavior; LLVM lowers the mapping to
//! arithmetic rather than the retail conditional-return sequence.

const STATE_POINTER_WORD: usize = 0xf00 / 4;
const NAVIGATION_STATE_WORD: usize = 0x18 / 4;

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn navigation_mode_from_state(owner: *const u32) -> u32 {
    let state = unsafe { owner.add(STATE_POINTER_WORD).read() } as usize as *const u32;
    match unsafe { state.add(NAVIGATION_STATE_WORD).read() } {
        1 => 2,
        2 => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_BYTES: usize = 0x2000;
    const OWNER_OFFSET: usize = 0x100;
    const STATE_OFFSET: usize = 0x1200;

    #[test]
    fn maps_only_the_two_recognized_navigation_states() {
        let Some(base) = (unsafe {
            try_map_u32_slab(hints::UI_NAVIGATION_MODE_FROM_STATE, FIXTURE_BYTES)
        }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        let owner = unsafe { base.add(OWNER_OFFSET).cast::<u32>() };
        let state = unsafe { base.add(STATE_OFFSET).cast::<u32>() };

        unsafe {
            owner.add(STATE_POINTER_WORD).write(state as usize as u32);
            for (raw_state, expected_mode) in [(0, 0), (1, 2), (2, 1), (3, 0), (u32::MAX, 0)] {
                state.add(NAVIGATION_STATE_WORD).write(raw_state);
                assert_eq!(navigation_mode_from_state(owner), expected_mode);
            }
        }
    }
}
