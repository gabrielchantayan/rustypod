//! Root media query zero predicate.
//!
//! Original `FUN_081115f4` @ **0x081115f4**, **24 bytes** through
//! 0x0811160c, where the next function starts with e92d4038. Raw words
//! verify one outgoing plain BL (0x081115fc -> 0x08051c1c), no predicated
//! BLs, and two incoming plain BLs (0x0812f338, 0x08177cf4), no predicated
//! callers. Load the word at root +0x30, call the media query, and return
//! exactly one for result zero, otherwise zero (RSBS / MOVCC).
//!
//! Deliberate deviations: keep unported 0x08051c1c as a verified retail
//! boundary; host builds install a native operation. Its raw body ignores
//! the argument and queries media_player_get (0x0817ceb4), returning 1 for
//! nonzero vtable slot +0x190, else 2 for nonzero +0x194, else 0. Preserve
//! the original argument load with a volatile aligned word read, even though
//! that callee ignores it. No guessed playback-state meaning is assigned.
//! Codegen review: LLVM preserves LDR +0x30 and calls literal 0x08051c1c
//! with BLX. CLZ / LSR #5 replaces RSBS / MOVCC with the same exact-zero
//! result; it saves fp instead of r4 and adds a frame-pointer setup.
//!

pub type MediaQuery = unsafe extern "C" fn(u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_media_query(_: u32) -> u32 {
    panic!("install media query (retail 0x08051c1c)")
}
#[cfg(not(target_os = "none"))]
pub static mut ROOT_MEDIA_QUERY: MediaQuery = missing_media_query;

/// Return one iff the retail media query returns zero.
///
/// # Safety
/// `root + 0x30` must be readable and word-aligned, and the media query
/// operation must be valid. The original performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn root_media_query_is_zero(root: *mut u8) -> u32 {
    let argument = unsafe { root.cast::<u32>().add(12).read_volatile() };
    #[cfg(target_os = "none")]
    let query: MediaQuery = unsafe { core::mem::transmute(0x08051c1cusize) };
    #[cfg(not(target_os = "none"))]
    let query = unsafe { ROOT_MEDIA_QUERY };
    (unsafe { query(argument) } == 0) as u32
}

#[cfg(test)]
pub(crate) static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    static mut RESULT: u32 = 0;
    unsafe extern "C" fn query(_: u32) -> u32 { unsafe { RESULT } }

    #[test]
    fn only_zero_is_true_including_unsigned_boundaries() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let saved = ROOT_MEDIA_QUERY;
            ROOT_MEDIA_QUERY = query;
            let mut root = [0u32; 13];
            for result in [0, 1, 2, 255, 256, 0x8000_0000, u32::MAX] {
                RESULT = result;
                assert_eq!(root_media_query_is_zero(root.as_mut_ptr().cast()),
                    (result == 0) as u32);
            }
            ROOT_MEDIA_QUERY = saved;
        }
    }
}
