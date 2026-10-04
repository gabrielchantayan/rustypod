//! `type_two_payload_construct` — retailOS `FUN_081fc9e4` @ `0x081fc9e4`.
//!
//! True extent: 32 bytes, `0x081fc9e4..0x081fca04`: 28 instruction bytes
//! through the return at `0x081fc9fc`, then the vtable literal at `0x081fca00`.
//! The next real function starts with `cmp r0,#0` at `0x081fca04`.
//! Whole-image ARM decoding finds two incoming plain BLs (`0x0818a398`,
//! `0x081fbfa0`), zero predicated BLs. One outgoing plain BL at `0x081fc9f0`
//! calls the shared constructor at `0x081fc9c0`; zero predicated outgoing BLs.
//!
//! Initialize the shared payload prefix with tag 2 and the supplied payload,
//! then install derived vtable `0x08990e6c`, returning this unchanged in r0.
//! Both callers allocate 12 bytes and retain the returned object pointer.
//! The concrete C++ class identity is unresolved. Deliberate deviations:
//! reuse the existing Rust base constructor and volatile store convention;
//! LLVM may use a different frame/register allocation. No validation added.

use super::vtable_tagged_payload_construct::vtable_tagged_payload_construct;

pub const TYPE_TWO_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0899_0e6c;

/// Construct the type-two derived payload prefix.
///
/// # Safety
/// `this` must point to at least 12 writable bytes, aligned for `u32` stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.type_two_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn type_two_payload_construct(this: *mut u8, payload: u32) -> *mut u8 {
    unsafe {
        let object = vtable_tagged_payload_construct(this, 2, payload);
        object.cast::<u32>().write_volatile(TYPE_TWO_PAYLOAD_VTABLE_ADDRESS);
        object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_padding_neighbors_and_all_payload_bits() {
        for pattern in [0_u32, 0xa5a5_a5a5, u32::MAX] {
            for payload in [0, 1, 0x8000_0000, 0x1234_5678, u32::MAX] {
                let mut words = [pattern; 5];
                let this = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
                let returned = unsafe { type_two_payload_construct(this, payload) };
                assert_eq!(returned, this);
                assert_eq!(words, [pattern, TYPE_TWO_PAYLOAD_VTABLE_ADDRESS,
                    (pattern & !0xff) | 2, payload, pattern]);
            }
        }
    }
}
