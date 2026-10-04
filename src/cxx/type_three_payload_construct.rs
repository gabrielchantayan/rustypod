//! `type_three_payload_construct` — retailOS `FUN_0820b8d0` @ `0x0820b8d0`.
//!
//! Raw ARM has 28 bytes of instructions through the return at `0x0820b8e8`;
//! the literal at `0x0820b8ec` makes the extent to the next real function at
//! `0x0820b8f0` 32 bytes. Verified incoming calls: two plain BLs at
//! `0x081fc010` and `0x08214278`, zero predicated BLs. One outgoing plain BL
//! calls the shared constructor at `0x081fc9c0`.
//!
//! Initialize the shared payload prefix with tag 3 and the supplied payload,
//! then install the derived vtable `0x08992230`, returning this unchanged.
//! The concrete C++ class identity is unresolved. Deliberate deviations:
//! reuse the existing Rust base constructor and volatile store convention;
//! LLVM may use a different frame/register allocation. No validation added.

use super::vtable_tagged_payload_construct::vtable_tagged_payload_construct;

pub const TYPE_THREE_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0899_2230;

/// Construct the type-three derived payload prefix.
///
/// # Safety
/// `this` must point to at least 12 writable bytes, aligned for `u32` stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.type_three_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn type_three_payload_construct(this: *mut u8, payload: u32) -> *mut u8 {
    unsafe {
        let object = vtable_tagged_payload_construct(this, 3, payload);
        object.cast::<u32>().write_volatile(TYPE_THREE_PAYLOAD_VTABLE_ADDRESS);
        object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_padding_neighbors_and_all_payload_bits() {
        for payload in [0, 1, 0x8000_0000, 0x1234_5678, u32::MAX] {
            let mut words = [0xa5a5_a5a5_u32; 5];
            let this = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
            let returned = unsafe { type_three_payload_construct(this, payload) };
            assert_eq!(returned, this);
            assert_eq!(words, [0xa5a5_a5a5, TYPE_THREE_PAYLOAD_VTABLE_ADDRESS,
                0xa5a5_a503, payload, 0xa5a5_a5a5]);
        }
    }
}
