//! `tagged_buffer_payload_address` — original: `FUN_082142ec` @ `0x082142ec`
//! (64 bytes; `0x082142ec..0x0821432c`).
//!
//! Whole-image A32 branch decoding finds four inbound plain unconditional `bl`
//! calls (`0x0818b51c`, `0x0818b6a4`, `0x0818b6f4`, and `0x082974e8`) and no
//! predicated `bl` calls. The body contains one unconditional `bl` to the
//! adjacent 20-byte alignment helper at `0x082142d8`; `bls 0x08214324` is a
//! predicated branch to this routine's return epilogue, not a callee.
//!
//! # Algorithm
//!
//! Flag `0x0800_0000` selects the encoded form. Clear returns the target-width
//! pointer stored at descriptor `+0x0c`. Set starts at `+0x0c`; its encoded
//! alignment class is flags `0x7000_0000 >> 26`. Classes through four leave
//! that address unchanged; higher classes round it up using the adjacent
//! helper's `(align - (address & (align - 1))) & (align - 1)` calculation.
//! The helper has no established name or Rust seam, so its verified arithmetic
//! is deliberately inlined; there are no other deviations.

/// Flag selecting an encoded, aligned in-object payload address.
pub const TAGGED_BUFFER_ENCODED_PAYLOAD: u32 = 0x0800_0000;

/// tagged_buffer_payload_address — original: `FUN_082142ec` @ `0x082142ec`
/// (64 bytes; 4 direct plain-`bl` call sites).
///
/// `descriptor` must be non-NULL, four-byte aligned, and readable through
/// `+0x0c`. In the direct form, word `+0x0c` is a 32-bit target pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_buffer_payload_address")]
#[inline(never)]
pub unsafe extern "C" fn tagged_buffer_payload_address(descriptor: *const u32) -> *mut u8 {
    let flags = descriptor.read();
    if flags & TAGGED_BUFFER_ENCODED_PAYLOAD == 0 {
        return descriptor.add(3).read() as usize as *mut u8;
    }

    let payload = descriptor.cast_mut().cast::<u8>().add(12);
    let alignment = ((flags & 0x7000_0000) >> 26) as usize;
    if alignment <= 4 {
        payload
    } else {
        payload.add((alignment - (payload as usize & (alignment - 1))) & (alignment - 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn resolves_direct_and_encoded_payload_forms_at_alignment_boundaries() {
        let Some(slab) = try_map_u32_slab(hints::TAGGED_BUFFER_PAYLOAD_ADDRESS, 0x1000) else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let descriptor = unsafe { slab.add(0x100).cast::<u32>() };
        let direct_payload = unsafe { slab.add(0x300) };

        unsafe {
            descriptor.write(0);
            descriptor.add(3).write(direct_payload as usize as u32);
            assert_eq!(tagged_buffer_payload_address(descriptor), direct_payload);

            for alignment in [0, 4, 8, 12, 16, 28] {
                descriptor.write(TAGGED_BUFFER_ENCODED_PAYLOAD | (alignment << 26));
                let payload = descriptor.cast::<u8>().add(12);
                let expected = if alignment <= 4 {
                    payload
                } else {
                    payload.add(((alignment as usize) - (payload as usize & (alignment as usize - 1))) & (alignment as usize - 1))
                };
                assert_eq!(tagged_buffer_payload_address(descriptor), expected, "alignment={alignment}");
            }
        }
    }
}
