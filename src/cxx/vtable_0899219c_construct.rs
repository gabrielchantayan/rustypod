//! `vtable_0899219c_construct` — original: `FUN_0820b20c` @ **0x0820b20c**.
//! 20 instruction bytes; 24 bytes including the literal pool through the next
//! real function boundary at 0x0820b224 (`cmp r0,#0`).
//!
//! Raw words: e52de004 ebfeadd4 e59f1004 e5801000 e49df004,
//! followed by the vtable literal 0899219c at 0x0820b220. Whole-image ARM
//! decoding finds two inbound plain BL calls (0x08148638 and 0x08177f1c),
//! no predicated BL callers. The body has one plain BL at 0x0820b210 to
//! 0x081b6968 and no predicated BL instructions.
//!
//! Forward `this` and `payload` to `vtable_flag_payload_construct`, overwrite
//! the returned object's +0 word with 0x0899219c, and return that same pointer.
//! No NULL or alignment guard exists. Deliberate deviations: none; the existing
//! callee's base-constructor seam remains unchanged. The class identity is not
//! established, so the name identifies the observed vtable rather than guessing.

use crate::cxx::vtable_flag_payload_construct::vtable_flag_payload_construct;

/// Derived vtable literal at 0x0820b220.
pub const VTABLE_0899219C_ADDRESS: u32 = 0x0899_219c;

/// Constructs the vtable/flag/payload prefix with vtable 0x0899219c.
///
/// # Safety
///
/// `this` and the base constructor's returned pointer must be four-byte aligned
/// and reference at least 12 writable bytes, as required by the existing callee.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_0899219c_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_0899219c_construct(this: *mut u8, payload: u32) -> *mut u8 {
    let result = unsafe { vtable_flag_payload_construct(this, payload) };
    unsafe { result.cast::<u32>().write(VTABLE_0899219C_ADDRESS) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_prefix_without_touching_padding_or_neighbors() {
        for payload in [0, 1, 0x8000_0000, u32::MAX] {
            let mut storage = [0xfeed_face_u32; 6];
            let object = unsafe { storage.as_mut_ptr().add(1).cast() };
            let result = unsafe { vtable_0899219c_construct(object, payload) };

            assert_eq!(result, object);
            assert_eq!(storage, [
                0xfeed_face, VTABLE_0899219C_ADDRESS, 0xfeed_fa00,
                payload, 0xfeed_face, 0xfeed_face,
            ]);
        }
    }
}
