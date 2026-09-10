//! `tagged_payload_signed_field_sum` — original: `FUN_082a1d7c` @ `0x082a1d7c`
//! (44 bytes; 10 verified direct `bl` call sites, all unconditional).
//!
//! Raw ARM runs from `0x082a1d7c` through `bx lr` at `0x082a1da4`; the next
//! separately linked function begins at `0x082a1da8`. It loads the target-width
//! word at `object + 0x20`, clears its low tag bit, and returns zero when that
//! leaves a NULL pointer. Otherwise it adds the three signed halfwords at
//! payload offsets `+0x52`, `+0x54`, and `+0x56`, then truncates the sum to a
//! signed 16-bit result. The surrounding object's concrete type is unrecovered,
//! so this port names only the observed tagged-payload operation.
//!
//! Deliberate deviation: pointer fields remain `u32` target words rather than
//! host-width pointers, preserving the firmware's `+0x20` layout on 64-bit
//! hosts. The raw pointer safety and alignment requirements of `ldrsh` remain.

const PAYLOAD_WORD: usize = 8;
const FIRST_SIGNED_FIELD: usize = 0x52 / core::mem::size_of::<i16>();

/// Returns the signed-16-bit sum of three adjacent fields in `object`'s tagged
/// payload.
///
/// # Safety
///
/// `object` must reference at least nine aligned target-width words. When its
/// word at `+0x20`, after clearing bit zero, is nonzero, it must be an aligned
/// readable payload containing signed halfwords through `+0x56`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tagged_payload_signed_field_sum(object: *const u32) -> i32 {
    let payload_word = unsafe { object.add(PAYLOAD_WORD).read() } & !1;
    if payload_word == 0 {
        return 0;
    }

    let fields = payload_word as usize as *const i16;
    let sum = unsafe {
        fields.add(FIRST_SIGNED_FIELD).read() as i32
            + fields.add(FIRST_SIGNED_FIELD + 1).read() as i32
            + fields.add(FIRST_SIGNED_FIELD + 2).read() as i32
    };
    sum as i16 as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_BYTES: usize = 0x1000;
    const PAYLOAD_OFFSET: usize = 0x100;

    fn reference(fields: [i16; 3]) -> i32 {
        (fields[0] as i32 + fields[1] as i32 + fields[2] as i32) as i16 as i32
    }

    #[test]
    fn null_and_tag_only_payloads_return_zero_without_dereferencing() {
        let mut object = [0u32; PAYLOAD_WORD + 1];

        unsafe {
            assert_eq!(tagged_payload_signed_field_sum(object.as_ptr()), 0);
            object[PAYLOAD_WORD] = 1;
            assert_eq!(tagged_payload_signed_field_sum(object.as_ptr()), 0);
        }
    }

    #[test]
    fn sums_signed_fields_clears_tag_and_truncates_to_i16() {
        let Some(slab) = try_map_u32_slab(hints::TAGGED_PAYLOAD_SIGNED_FIELD_SUM, FIXTURE_BYTES)
        else {
            note_missing_u32_fixture(module_path!());
            return;
        };

        let object = slab.cast::<u32>();
        let payload = unsafe { slab.add(PAYLOAD_OFFSET).cast::<i16>() };
        let cases = [
            [1, 2, 3],
            [-1, 0, 0],
            [i16::MAX, i16::MAX, 1],
            [i16::MIN, i16::MIN, 0],
            [i16::MIN, i16::MIN, i16::MIN],
        ];

        for fields in cases {
            unsafe {
                object.add(PAYLOAD_WORD).write(payload as usize as u32 | 1);
                payload.add(FIRST_SIGNED_FIELD).write(fields[0]);
                payload.add(FIRST_SIGNED_FIELD + 1).write(fields[1]);
                payload.add(FIRST_SIGNED_FIELD + 2).write(fields[2]);
                assert_eq!(tagged_payload_signed_field_sum(object), reference(fields));
            }
        }
    }
}
