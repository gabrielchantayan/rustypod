//! Root media query zero predicate.
//!
//! Original `FUN_081115f4` @ **0x081115f4**, **24 bytes** through
//! 0x0811160c, where the next function starts with e92d4038. Raw words
//! verify one outgoing plain BL (0x081115fc -> 0x08051c1c), no predicated
//! BLs, and two incoming plain BLs (0x0812f338, 0x08177cf4), no predicated
//! callers. Load the word at root +0x30, call the media query, and return
//! exactly one for result zero, otherwise zero (RSBS / MOVCC).
//!
//! Deliberate deviation: preserve the unused argument load with a volatile
//! aligned word read; call the canonical media_player_query_code port.
//! Its result codes carry no guessed playback-state meaning.

/// Return one iff the retail media query returns zero.
///
/// # Safety
/// `root + 0x30` must be readable and word-aligned, and the media query
/// operation must be valid. The original performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn root_media_query_is_zero(root: *mut u8) -> u32 {
    let _argument = unsafe { root.cast::<u32>().add(12).read_volatile() };
    (unsafe { super::media_player_query_code::media_player_query_code() } == 0) as u32
}

