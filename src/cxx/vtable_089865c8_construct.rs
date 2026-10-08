//! `vtable_089865c8_construct` — original: `FUN_0814878c` @ **0x0814878c**.
//! 20 instruction bytes plus a four-byte literal pool (24 bytes through the
//! next real function boundary at 0x081487a4).
//!
//! Raw ARM: push {r4,lr}; bl 0x081b6968; ldr r1,[pc,#4]; str r1,[r0];
//! pop {r4,pc}. The literal at 0x081487a0 is 0x089865c8. Whole-image word
//! decoding finds two inbound plain BL calls, at 0x08148060 and 0x0814861c,
//! and zero predicated BL calls. The sole outbound BL is unconditional at
//! 0x08148790; there are no outbound predicated calls.
//!
//! Forward this and payload to the existing flag/payload prefix constructor,
//! replace the returned object's vtable, and return that same pointer. Callers
//! use a 12-byte stack prefix or an embedded prefix with zero payload.
//! Deliberate deviations: none; reuse the direct Rust prefix and base ports.
//! The wider class identity remains unestablished.

use super::vtable_flag_payload_construct::vtable_flag_payload_construct;

pub const VTABLE_089865C8_ADDRESS: u32 = 0x0898_65c8;

/// Construct the observed derived flag/payload prefix.
///
/// # Safety
/// `this` and the base constructor's returned pointer must provide at least
/// 12 writable bytes, aligned to four bytes. There is no NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_089865c8_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_089865c8_construct(this: *mut u8, payload: u32) -> *mut u8 {
    let result = unsafe { vtable_flag_payload_construct(this, payload) };
    unsafe { result.cast::<u32>().write(VTABLE_089865C8_ADDRESS) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_prefix_without_touching_padding_or_adjacent_objects() {
        for payload in [0, 0x1357_9bdf, u32::MAX] {
            let mut words = [0xa5a5_a5a5_u32; 5];
            let object = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
            let returned = unsafe { vtable_089865c8_construct(object, payload) };
            assert_eq!(returned, object);
            assert_eq!(words, [0xa5a5_a5a5, VTABLE_089865C8_ADDRESS,
                0xa5a5_a500, payload, 0xa5a5_a5a5]);
        }
    }
}
