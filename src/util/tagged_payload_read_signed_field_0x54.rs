//! `tagged_payload_read_signed_field_0x54` — original: `FUN_082a1da8` @
//! `0x082a1da8` (20 bytes; 7 verified direct `bl` call sites, all
//! unconditional).
//!
//! Raw ARM runs from `0x082a1da8` through `bx lr` at `0x082a1db8`; the next
//! separately linked function begins at `0x082a1dbc`. It loads the target-width
//! word at `object + 0x20`, clears its low tag bit, and returns zero when that
//! produces NULL. Otherwise it sign-extends and returns the halfword at payload
//! offset `+0x54`. The concrete object and payload types are unrecovered, so the
//! name records only this observed tagged-payload operation.
//!
//! Deliberate deviation: pointer fields remain `u32` target words rather than
//! host-width pointers, preserving the firmware's `+0x20` layout on 64-bit
//! hosts. The raw pointer safety and alignment requirements of `ldrsh` remain.

const PAYLOAD_WORD: usize = 8;
const SIGNED_FIELD: usize = 0x54 / core::mem::size_of::<i16>();

/// Returns the signed field at `+0x54` in `object`'s tagged payload.
///
/// # Safety
///
/// `object` must reference at least nine aligned target-width words. When its
/// word at `+0x20`, after clearing bit zero, is nonzero, it must be an aligned
/// readable payload containing a signed halfword at `+0x54`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.tagged_payload_read_signed_field_0x54"
)]
#[inline(never)]
pub unsafe extern "C" fn tagged_payload_read_signed_field_0x54(object: *const u32) -> i32 {
    let payload_word = unsafe { object.add(PAYLOAD_WORD).read() } & !1;
    if payload_word == 0 {
        return 0;
    }

    unsafe { (payload_word as usize as *const i16).add(SIGNED_FIELD).read() as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_BYTES: usize = 0x1000;
    const PAYLOAD_OFFSET: usize = 0x100;

    #[test]
    fn null_and_tag_only_payloads_return_zero_without_dereferencing() {
        let mut object = [0u32; PAYLOAD_WORD + 1];

        unsafe {
            assert_eq!(tagged_payload_read_signed_field_0x54(object.as_ptr()), 0);
            object[PAYLOAD_WORD] = 1;
            assert_eq!(tagged_payload_read_signed_field_0x54(object.as_ptr()), 0);
        }
    }

    #[test]
    fn clears_tag_and_sign_extends_payload_field() {
        let Some(slab) = try_map_u32_slab(
            hints::TAGGED_PAYLOAD_READ_SIGNED_FIELD_0X54,
            FIXTURE_BYTES,
        ) else {
            note_missing_u32_fixture(module_path!());
            return;
        };

        let object = slab.cast::<u32>();
        let payload = unsafe { slab.add(PAYLOAD_OFFSET).cast::<i16>() };
        let cases = [i16::MIN, -1, 0, 1, i16::MAX];

        for field in cases {
            unsafe {
                object.add(PAYLOAD_WORD).write(payload as usize as u32 | 1);
                payload.add(SIGNED_FIELD).write(field);
                assert_eq!(tagged_payload_read_signed_field_0x54(object), field as i32);
            }
        }
    }
}
