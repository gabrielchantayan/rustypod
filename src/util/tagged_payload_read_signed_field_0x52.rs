//! `tagged_payload_read_signed_field_0x52` — original: `FUN_082a1d74` @
//! `0x082a1d74` (8 bytes; 7 verified direct `bl` call sites, all
//! unconditional).
//!
//! Raw ARM is exactly `add r0,r0,#0x20; b 0x0829be90`; the separately linked
//! sibling `tagged_payload_signed_field_sum` starts at `0x082a1d7c`. The tail
//! target loads the word at `object + 0x20`, clears bit zero, returns zero when
//! that is NULL, and otherwise sign-extends the halfword at the payload's
//! `+0x52` offset. Its concrete identity is unrecovered, so this name records
//! only the verified tagged-payload operation.
//!
//! Deliberate deviation: Rust materializes the tail target's four-instruction
//! field read rather than adding a dispatch seam for the unported,
//! identity-unrecovered `0x0829be90` entry. Pointer fields remain `u32` target
//! words, preserving the firmware's 32-bit layout on 64-bit hosts.

const PAYLOAD_WORD: usize = 0x20 / core::mem::size_of::<u32>();
const SIGNED_FIELD: usize = 0x52 / core::mem::size_of::<i16>();

/// Returns the signed field at `+0x52` in the tagged payload at `object + 0x20`.
///
/// # Safety
///
/// `object` must reference at least nine aligned target-width words. When its
/// word at `+0x20`, after clearing bit zero, is nonzero, it must identify an
/// aligned readable payload containing a signed halfword at `+0x52`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.tagged_payload_read_signed_field_0x52"
)]
#[inline(never)]
pub unsafe extern "C" fn tagged_payload_read_signed_field_0x52(object: *const u32) -> i32 {
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
    const PAYLOAD_OFFSET: usize = 0x200;

    #[test]
    fn null_and_tag_only_payloads_return_zero_without_dereferencing() {
        let Some(slab) = try_map_u32_slab(
            hints::TAGGED_PAYLOAD_READ_SIGNED_FIELD_0X52,
            FIXTURE_BYTES,
        ) else {
            note_missing_u32_fixture(module_path!());
            return;
        };

        let object = slab.cast::<u32>();
        unsafe {
            object.add(PAYLOAD_WORD).write(0);
            assert_eq!(tagged_payload_read_signed_field_0x52(object), 0);
            object.add(PAYLOAD_WORD).write(1);
            assert_eq!(tagged_payload_read_signed_field_0x52(object), 0);
        }
    }

    #[test]
    fn clears_tag_and_sign_extends_payload_field() {
        let Some(slab) = try_map_u32_slab(
            hints::TAGGED_PAYLOAD_READ_SIGNED_FIELD_0X52,
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
                assert_eq!(tagged_payload_read_signed_field_0x52(object), field as i32);
            }
        }
    }
}
