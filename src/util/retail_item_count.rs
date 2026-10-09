//! `retail_item_count` — original: `FUN_080ffa00` @ **0x080ffa00**.
//! True size: 8 bytes (`0x080ffa00..0x080ffa08`); the next function starts
//! at 0x080ffa08. Raw words are `e3a000cd` (mov r0, #205) and `e12fff1e`
//! (bx lr). Two plain inbound BLs, zero predicated inbound BLs, and no
//! outbound calls. Returns the fixed item count used by selection wraparound;
//! no arguments, memory accesses, or deliberate behavioral deviations.

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn retail_item_count() -> u32 {
    205
}
