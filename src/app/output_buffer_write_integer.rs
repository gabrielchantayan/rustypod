//! `output_buffer_write_integer` — `FUN_08123aa4` @ **0x08123aa4**.
//! True size: 64 instruction bytes [0x08123aa4,0x08123ae4), followed by
//! 28 format-literal bytes; next real function starts at 0x08123b00.
//! Two outgoing plain BLs, zero predicated BLs, and a tail B to 0x08123c58.
//! Two incoming plain BLs (0x08078bec, 0x080b5800), zero predicated BLs.
//!
//! Prepare indentation at state+0x215, render "%s<integer>%u</integer>\n"
//! into the 512-byte scratch at +0x15, then append the resulting C string.
//! Deliberate deviations: render this fixed format directly rather than use
//! the Rust snprintf port's placeholder engine. Decimal conversion uses a
//! ten-byte stack buffer; truncation and NUL termination match snprintf.
//! Reuse the existing firmware-bound indentation/appender seams, including
//! the original runtime indentation table, rather than guess its contents.
//! The original tail branch becomes a call and return.

use crate::app::output_buffer_reset::OutputBufferState;
use crate::app::output_buffer_write_dictionary_close::{
    OUTPUT_BUFFER_APPEND_C_STRING, OUTPUT_BUFFER_WRITE_INDENTATION,
};

// `destination` has 512 writable bytes; `indentation` is a readable C string.
unsafe fn render_integer(destination: *mut u8, indentation: *const u8, value: u32) {
    let mut written = 0usize;
    let mut source = indentation;
    while source.read() != 0 {
        if written < 511 {
            destination.add(written).write_volatile(source.read());
            written += 1;
        }
        source = source.add(1);
    }
    let mut digits = [0u8; 10];
    let mut first = digits.len();
    let mut remaining = value;
    loop {
        first -= 1;
        digits[first] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 { break; }
    }
    for part in [b"<integer>".as_slice(), &digits[first..], b"</integer>\n".as_slice()] {
        for &byte in part {
            if written < 511 {
                destination.add(written).write_volatile(byte);
                written += 1;
            }
        }
    }
    destination.add(written).write_volatile(0);
}

/// Emit one unsigned integer element.
///
/// # Safety
/// `state` must have the retail layout, 512 writable scratch bytes at +0x15,
/// and sufficient indentation storage at +0x215 for `level`. The installed
/// indentation and append operations must obey their firmware contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn output_buffer_write_integer(
    state: *mut OutputBufferState, value: u32, level: u32,
) {
    let indent = core::ptr::addr_of!(OUTPUT_BUFFER_WRITE_INDENTATION).read_volatile();
    indent(state, level);
    let scratch = (state as *mut u8).add(0x15);
    render_integer(scratch, scratch.add(0x200), value);
    let append = core::ptr::addr_of!(OUTPUT_BUFFER_APPEND_C_STRING).read_volatile();
    append(state, scratch);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::render_integer;

    #[test]
    fn unsigned_decimal_boundaries_and_indentation() {
        for value in [0, 1, 9, 10, 99, 100, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
            for indent in [b"\0".as_slice(), b"\t\t\0".as_slice()] {
                let mut output = [0xa5; 514];
                unsafe { render_integer(output.as_mut_ptr().add(1), indent.as_ptr(), value); }
                let prefix = std::str::from_utf8(&indent[..indent.len() - 1]).unwrap();
                let expected = std::format!("{prefix}<integer>{value}</integer>\n\0");
                assert_eq!(&output[1..1 + expected.len()], expected.as_bytes());
                assert_eq!(output[0], 0xa5);
                assert_eq!(output[1 + expected.len()], 0xa5);
            }
        }
    }

    #[test]
    fn truncation_preserves_nul_and_adjacent_storage() {
        for length in [480, 481, 490, 510, 511, 512, 600] {
            let mut indent = std::vec![b' '; length];
            indent.push(0);
            let mut output = [0xa5; 514];
            unsafe { render_integer(output.as_mut_ptr().add(1), indent.as_ptr(), u32::MAX); }
            let expected = std::format!("{}<integer>4294967295</integer>\n", " ".repeat(length));
            let used = expected.len().min(511);
            assert_eq!(&output[1..1 + used], &expected.as_bytes()[..used]);
            assert_eq!(output[1 + used], 0);
            assert_eq!(output[0], 0xa5);
            assert_eq!(output[513], 0xa5);
        }
    }
}
