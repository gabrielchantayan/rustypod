//! `type_one_payload_construct` — retailOS `FUN_0820768c` @ `0x0820768c`.
//!
//! True extent: 32 bytes, `0x0820768c..0x082076ac`: 28 instruction bytes
//! through the return at `0x082076a4`, then vtable literal `0x089919c0`
//! at `0x082076a8`. The next real function starts with `cmp r0,#0`.
//! Whole-image ARM decoding finds two incoming plain BLs (`0x0818a3cc`,
//! `0x081f0134`), zero predicated BLs. One outgoing plain BL at `0x08207698`
//! calls the shared constructor at `0x081fc9c0`; zero predicated outgoing BLs.
//!
//! Initialize the shared prefix with tag 1 and the full-width payload, replace
//! the vtable, and return this unchanged. The manager allocates twelve bytes;
//! the derived caller replaces the vtable again and stores a word at +12.
//! Concrete class identity is unresolved. Deliberate deviations: reuse the
//! existing Rust base constructor and volatile ordered stores; LLVM may change
//! frame/register allocation. No validation or padding initialization added.

use super::vtable_tagged_payload_construct::vtable_tagged_payload_construct;

pub const TYPE_ONE_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0899_19c0;

/// Construct the type-one derived payload prefix.
///
/// # Safety
/// `this` must point to at least 12 writable bytes, aligned for `u32` stores.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.type_one_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn type_one_payload_construct(this: *mut u8, payload: u32) -> *mut u8 {
    unsafe {
        let object = vtable_tagged_payload_construct(this, 1, payload);
        object.cast::<u32>().write_volatile(TYPE_ONE_PAYLOAD_VTABLE_ADDRESS);
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
                let returned = unsafe { type_one_payload_construct(this, payload) };
                assert_eq!(returned, this);
                assert_eq!(words, [pattern, TYPE_ONE_PAYLOAD_VTABLE_ADDRESS,
                    (pattern & !0xff) | 1, payload, pattern]);
            }
        }
    }
}
