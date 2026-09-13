//! `tagged_payload_word_read_signed_field_0x52` — original: `FUN_0829be90` @
//! `0x0829be90` (20 bytes; 6 verified direct `bl` call sites, all
//! unconditional; one direct tail branch).
//!
//! Raw ARM runs from `0x0829be90` through `bx lr` at `0x0829bea0`; the next
//! separately linked function starts at `0x0829bea4`. It loads a target-width
//! tagged payload word, clears bit zero, returns zero when that produces NULL,
//! and otherwise sign-extends the halfword at payload offset `+0x52`. The
//! concrete payload type is unrecovered, so the name records only this observed
//! tagged-payload-word operation.
//!
//! Deliberate deviation: the tagged pointer remains a `u32` target word rather
//! than a host-width pointer, preserving the firmware ABI on 64-bit hosts.

const SIGNED_FIELD: usize = 0x52 / core::mem::size_of::<i16>();

/// Returns the signed field at `+0x52` from a tagged payload word.
///
/// # Safety
///
/// `tagged_payload_word` must point to an aligned readable target-width word.
/// When that word, after clearing bit zero, is nonzero, it must identify an
/// aligned readable payload containing a signed halfword at `+0x52`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.tagged_payload_word_read_signed_field_0x52"
)]
#[inline(never)]
pub unsafe extern "C" fn tagged_payload_word_read_signed_field_0x52(
    tagged_payload_word: *const u32,
) -> i32 {
    let payload_word = unsafe { tagged_payload_word.read() } & !1;
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
    fn null_and_tag_only_payload_words_return_zero_without_dereferencing() {
        let mut tagged_payload_word = 0u32;

        unsafe {
            assert_eq!(tagged_payload_word_read_signed_field_0x52(&tagged_payload_word), 0);
            tagged_payload_word = 1;
            assert_eq!(tagged_payload_word_read_signed_field_0x52(&tagged_payload_word), 0);
        }
    }

    #[test]
    fn clears_tag_and_sign_extends_the_payload_field() {
        let Some(slab) = try_map_u32_slab(
            hints::TAGGED_PAYLOAD_WORD_READ_SIGNED_FIELD_0X52,
            FIXTURE_BYTES,
        ) else {
            note_missing_u32_fixture(module_path!());
            return;
        };

        let tagged_payload_word = slab.cast::<u32>();
        let payload = unsafe { slab.add(PAYLOAD_OFFSET).cast::<i16>() };

        for field in [i16::MIN, -1, 0, 1, i16::MAX] {
            unsafe {
                tagged_payload_word.write(payload as usize as u32 | 1);
                payload.add(SIGNED_FIELD).write(field);
                assert_eq!(
                    tagged_payload_word_read_signed_field_0x52(tagged_payload_word),
                    field as i32
                );
            }
        }
    }
}
