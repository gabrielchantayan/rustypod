//! Last payload word to shared time text: FUN_0829b654 @ 0x0829b654.
//! 48 bytes, three outgoing plain BLs, zero predicated BLs. Resolves and
//! copies four words, then formats the last word by address. Reuses the
//! existing Rust resolver, paired copy, and seconds_time_text ports.

use crate::copy_four_words::copy_four_words_paired;
use crate::object_word_payload_resolve::object_word_payload_resolve;
use crate::time::seconds_time_text::seconds_time_text;

/// # Safety
/// `object` must satisfy the payload resolver's contract, and the singleton
/// formatting service must satisfy `seconds_time_text`'s contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_payload_time_text(object: *mut u32) -> *const u8 {
    let mut resolved = [0u32; 4];
    let mut copied = [0u32; 4];
    unsafe {
        object_word_payload_resolve(resolved.as_mut_ptr(), object);
        copy_four_words_paired(copied.as_mut_ptr(), resolved.as_ptr());
        seconds_time_text(copied.as_ptr().add(3))
    }
}
