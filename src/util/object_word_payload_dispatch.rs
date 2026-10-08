//! Second payload word to shared time text: FUN_0829b734 @ 0x0829b734.
//! True extent 48 bytes through 0x0829b764. Three plain outgoing BLs,
//! zero predicated BLs. Raw code resolves at sp+20, copies at sp+4, then
//! passes sp+8 (the second copied word's address) to seconds_time_text.
//! The earlier operation-key signature was incorrect. Reuse existing Rust
//! ports; no firmware-address seams or incoming r1-r3 arguments remain.

use crate::copy_four_words::copy_four_words_paired;
use crate::object_word_payload_resolve::object_word_payload_resolve;
use crate::time::seconds_time_text::seconds_time_text;

/// # Safety
/// `object` must satisfy the payload resolver's contract, and the singleton
/// formatting service must satisfy `seconds_time_text`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_word_payload_dispatch(object: *mut u32) -> *const u8 {
    let mut resolved = [0u32; 4];
    let mut copied = [0u32; 4];
    unsafe {
        object_word_payload_resolve(resolved.as_mut_ptr(), object);
        copy_four_words_paired(copied.as_mut_ptr(), resolved.as_ptr());
        seconds_time_text(copied.as_ptr().add(1))
    }
}
