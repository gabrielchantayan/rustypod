//! `vtable_flag_construct` — original: `FUN_08135ba4` @ **0x08135ba4**
//! (20 instruction bytes, followed by its four-byte literal-pool vtable word
//! at 0x08135bb8).
//!
//! # Extent and reachability, binary-verified
//!
//! Raw ARM runs from `push {lr}` at 0x08135ba4 through `pop {pc}` at
//! 0x08135bb4. The following pool word is `0x08984a44`; the separately linked
//! next function starts at 0x08135bbc (`cmp r0,#0`). Whole-image decoding
//! finds exactly three direct inbound calls, all unconditional plain `bl` at
//! 0x08148054, 0x08148644, and 0x081e1670. It has one direct, unconditional
//! plain `bl` call at 0x08135ba8 to `vtable_flag_payload_construct`; no
//! predicated `bl` calls occur.
//!
//! # Algorithm
//!
//! Forward `this` and `payload` to the derived prefix constructor, replace the
//! returned object's vtable with `0x08984a44`, then return that same pointer.
//! No argument, NULL, or alignment guard exists.
//!
//! # Deliberate deviations
//!
//! None. The callee is an existing direct Rust port; its established seam for
//! the still-unported shared base constructor remains below this boundary.

use crate::cxx::vtable_flag_payload_construct::vtable_flag_payload_construct;

/// Vtable literal at 0x08135bb8.
pub const VTABLE_FLAG_VTABLE_ADDRESS: u32 = 0x0898_4a44;

/// Constructs the observed vtable/flag prefix and returns the callee's result.
///
/// # Safety
///
/// `this`, and the pointer returned by the prefix constructor, must point to
/// at least four writable, four-byte-aligned bytes. The retail function
/// dereferences the result without a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_flag_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_construct(this: *mut u8, payload: u32) -> *mut u8 {
    let result = unsafe { vtable_flag_payload_construct(this, payload) };
    unsafe { result.cast::<u32>().write(VTABLE_FLAG_VTABLE_ADDRESS) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::vtable_flag_payload_construct::VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS;

    #[test]
    fn constructs_derived_prefix_and_preserves_payload() {
        let mut object = [0xfeed_face_u32; 4];

        let result = unsafe { vtable_flag_construct(object.as_mut_ptr().cast(), 0x1357_9bdf) };

        assert_eq!(result, object.as_mut_ptr().cast());
        assert_eq!(object[0], VTABLE_FLAG_VTABLE_ADDRESS);
        assert_eq!(object[1] & 0xff, 0);
        assert_eq!(object[2], 0x1357_9bdf);
        assert_eq!(object[3], 0xfeed_face);
        assert_ne!(object[0], VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS);
    }
}
