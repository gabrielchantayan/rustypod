//! `length_prefix_validate` — original: `FUN_0804491c` @ `0x0804491c`
//! (40-byte body; `0x030e` literal at `0x08044944`).
//!
//! Raw `osos.dec` places the next independently linked function at
//! `0x08044948`. This is a leaf: zero outbound `bl` calls; five inbound plain
//! `bl` calls at `0x0804827c`, `0x08058be0`, `0x080647c4`, `0x08065e68`, and
//! `0x08065f54`; no predicated calls.
//!
//! The context's bit 1 selects an 8- or 16-bit little-endian length prefix.
//! The prefix is valid only from 6 through the context's `+0x1e` u16 limit;
//! all other values return `0x030e`. The predicated original does not read the
//! limit for values below 6, which this port preserves. Deliberate deviation:
//! structured Rust conditionals replace ARM predication; observable reads and
//! results are unchanged.

use super::managed_entry_selector::LengthPrefixedRequestContext;
use core::ptr;


const WIDE_LENGTH_FLAG: u32 = 2;
const MINIMUM_LENGTH: u32 = 6;
const LENGTH_OUT_OF_RANGE: u32 = 0x030e;

/// Validates an 8- or 16-bit prefix against the context's allowed range.
///
/// # Safety
///
/// `input` must be readable as a `u8`, or aligned and readable as a `u16` when
/// context bit 1 is set. `context` must be readable through `+0x34`; its
/// `length_limit` is read only when the decoded prefix is at least six.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn length_prefix_validate(
    input: *const u8,
    context: *const LengthPrefixedRequestContext,
) -> u32 {
    let flags = ptr::read_volatile(ptr::addr_of!((*context).flags));
    let length = if (flags & WIDE_LENGTH_FLAG) == 0 {
        input.read() as u32
    } else {
        input.cast::<u16>().read() as u32
    };

    if length >= MINIMUM_LENGTH && length <= (*context).length_limit as u32 {
        0
    } else {
        LENGTH_OUT_OF_RANGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(flags: u32, length_limit: u16) -> LengthPrefixedRequestContext {
        LengthPrefixedRequestContext {
            opaque_00: [0; 0x1e],
            length_limit,
            opaque_20: [0; 0x10],
            flags,
        }
    }

    #[test]
    fn byte_prefix_accepts_only_the_closed_context_range() {
        let context = context(0, 9);
        for (length, expected) in [(0u8, LENGTH_OUT_OF_RANGE), (5, LENGTH_OUT_OF_RANGE), (6, 0), (9, 0), (10, LENGTH_OUT_OF_RANGE), (u8::MAX, LENGTH_OUT_OF_RANGE)] {
            assert_eq!(unsafe { length_prefix_validate(&length, &context) }, expected, "{length}");
        }
    }

    #[test]
    fn wide_prefix_uses_the_u16_value_and_same_boundaries() {
        let context = context(WIDE_LENGTH_FLAG, 0x1234);
        for (length, expected) in [(5u16, LENGTH_OUT_OF_RANGE), (6, 0), (0x1234, 0), (0x1235, LENGTH_OUT_OF_RANGE), (u16::MAX, LENGTH_OUT_OF_RANGE)] {
            assert_eq!(unsafe { length_prefix_validate((&length as *const u16).cast(), &context) }, expected, "{length:#x}");
        }
    }
}
