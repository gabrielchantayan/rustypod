//! Default error result for an unsupported record-resource parser selector.

use crate::app::parse_result::{parse_result_init, parse_result_init_alias_3134};

/// Original: `FUN_080fc74c` @ 0x080fc74c, 40 bytes, ending at the next
/// function's `push` at 0x080fc774. Binary scan verifies two plain inbound
/// `bl` sites (0x080f8b88 and 0x080fc3d0), zero predicated inbound `bl`.
/// The body has one plain `bl`, zero predicated `bl`, and one tail `b`.
///
/// Clears the four-byte parser result through 0x08283168, then rewrites it
/// through 0x08283134 as {status: 2, code: 5, detail: 0x2000}. The callers
/// select this path for unsupported primary or secondary parser selectors.
/// Returns the output pointer preserved in r0 by both original callees.
/// Deliberate deviations: none in behavior; Rust expresses the tail branch
/// as a call expression, with tail-call selection left to LLVM. Unused
/// caller registers r1/r2 are not arguments of this function.
///
/// # Safety
/// `out` must cover four writable bytes and be halfword-aligned.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parse_result_unsupported(out: *mut u8) -> *mut u8 {
    let out = parse_result_init(out, 0, 0, 0);
    parse_result_init_alias_3134(out, 2, 5, 0x2000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct Buffer([u8; 12]);

    #[test]
    fn overwrites_every_prior_byte_at_both_halfword_alignments() {
        for offset in [4, 6] {
            for prior in 0..=u8::MAX {
                let mut buffer = Buffer([prior; 12]);
                let out = unsafe { buffer.0.as_mut_ptr().add(offset) };
                let returned = unsafe { parse_result_unsupported(out) };
                assert_eq!(returned, out);
                let mut expected = [prior; 12];
                expected[offset..offset + 4].copy_from_slice(&[2, 5, 0, 0x20]);
                assert_eq!(buffer.0, expected);
                assert_eq!(unsafe { parse_result_unsupported(out) }, out);
                assert_eq!(buffer.0, expected);
            }
        }
    }
}
