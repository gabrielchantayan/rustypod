//! Dispatch a byte/halfword payload through the UI manager.
//!
//! Original: FUN_081b0fe8 @ 0x081b0fe8. True extent 44 bytes: 40 bytes
//! of instructions and the literal at 0x081b1010; the next function starts
//! at 0x081b1014. Raw A32 decoding verifies two outgoing unconditional BLs,
//! zero predicated BLs, and two incoming unconditional BLs (zero predicated).
//! Push r3, overwrite byte 0 with r0 and halfword 2 with r1, acquire the
//! manager, load the dispatch key from 0x089cb238, and dispatch with count 1.
//!
//! Deviations: reuse ui_manager_instance instead of its 0x08037f88 veneer.
//! Preserve byte 1 of incoming r3, although callers do not explicitly supply
//! it as an argument. r2 is unused. The verified 0x08038110 veneer points to
//! IRAM 0x2200508c (raw mirror 0x0800508c adds 8 to r0 and tail-branches).
//! That unported operation remains a target-only retailOS seam; host calls
//! fail explicitly rather than pretend to dispatch. No padding is invented.

#[inline(always)]
fn payload_word(kind: u32, value: u32, incoming_r3: u32) -> u32 {
    (kind & 0xff) | (incoming_r3 & 0xff00) | ((value & 0xffff) << 16)
}

/// # Safety
/// retailOS must have initialized the manager and the dispatch key at
/// 0x089cb238. The downstream operation must consume the stack payload before
/// returning. `incoming_r3` models the original saved register, not a new
/// logical parameter; its bits 8..15 are observable payload bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_dispatch_byte_halfword(
    kind: u32, value: u32, _unused_r2: u32, incoming_r3: u32,
) {
    let payload = payload_word(kind, value, incoming_r3);
    #[cfg(target_os = "none")]
    {
        let manager = crate::ui::manager::ui_manager_instance();
        let key = core::ptr::read_volatile(0x089c_b238usize as *const u32);
        let dispatch: unsafe extern "C" fn(*mut u8, u32, u32, *const u32) =
            core::mem::transmute(0x2200_508cusize);
        dispatch(manager, key, 1, &payload);
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = payload;
        panic!("UI manager operation at 0x2200508c requires retailOS");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_stores_match_little_endian_payload_bytes() {
        for kind in [0, 1, 0xff, 0x100, u32::MAX] {
            for value in [0, 1, 0x8000, 0xffff, 0x10000, u32::MAX] {
                for incoming in [0, 0x1234_5678, 0x0000_ff00, u32::MAX] {
                    let mut reference = incoming.to_le_bytes();
                    reference[0] = kind as u8;
                    reference[2..4].copy_from_slice(&(value as u16).to_le_bytes());
                    assert_eq!(payload_word(kind, value, incoming).to_le_bytes(), reference);
                }
            }
        }
    }

    #[test]
    fn saved_register_only_contributes_second_byte() {
        assert_eq!(payload_word(0x1234, 0x5678, 0xaabb_ccdd), 0x5678_cc34);
        assert_eq!(payload_word(0x1234, 0x5678, 0x0011_cc00), 0x5678_cc34);
    }
}
