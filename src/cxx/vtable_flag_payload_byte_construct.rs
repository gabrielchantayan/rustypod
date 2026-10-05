//! `vtable_flag_payload_byte_construct` — `FUN_081ba980` @ **0x081ba980**.
//! True extent: 32 bytes (28 instruction bytes, then literal 0x0898c7f4 at
//! 0x081ba99c); next function starts at 0x081ba9a0 with `cmp r0,#0`.
//! Whole-image ARM immediate decoding verifies two inbound plain BL calls
//! (0x08148048, 0x0814862c), zero predicated BL calls, and one outbound plain
//! BL at 0x081ba988 to the existing 0x081b6968 payload constructor.
//!
//! Preserve the incoming state byte across the payload constructor, install
//! vtable 0x0898c7f4 on its returned object, store the byte at +12, and return
//! that pointer. The base clears byte +4 and stores the payload at +8.
//! Deliberate deviations: none at this boundary; reuse the callee's existing
//! base-constructor seam. The wider class identity remains unestablished.

use super::vtable_flag_payload_construct::vtable_flag_payload_construct;

pub const VTABLE_FLAG_PAYLOAD_BYTE_VTABLE_ADDRESS: u32 = 0x0898_c7f4;

/// Constructs a payload prefix with an additional state byte.
///
/// # Safety
/// `this` and the base constructor's returned pointer must provide at least
/// 13 writable bytes, aligned to four bytes. Neither pointer is NULL-checked.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_flag_payload_byte_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_payload_byte_construct(
    this: *mut u8,
    payload: u32,
    state: u8,
) -> *mut u8 {
    let result = unsafe { vtable_flag_payload_construct(this, payload) };
    unsafe {
        result.cast::<u32>().write(VTABLE_FLAG_PAYLOAD_BYTE_VTABLE_ADDRESS);
        result.add(12).write(state);
    }
    result
}
