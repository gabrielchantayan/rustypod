//! `output_buffer_write_keyed_i64` — `FUN_081237b8` @ **0x081237b8**.
//! True extent: 80 instruction bytes [0x081237b8,0x08123808), then 44
//! format/padding bytes; next real PUSH boundary is 0x08123834.
//! Raw A32 census: two incoming plain BLs (0x080b5578,0x080b55c4),
//! two outgoing plain BLs, zero predicated BLs, tail B to 0x08123c58.
//! Prepare indentation, format "%s<key>%s</key>\n%s<integer>%lld</integer>\n"
//! in the 512-byte scratch at +0x15, then append its terminated contents.
//! Deviations: allocation-free fixed-format rendering replaces the placeholder
//! Rust snprintf engine. Reuse firmware-bound indentation/appender seams to
//! retain the runtime table rather than the existing Rust guessed table.
//! Tail B becomes call/return. Signed conversion includes INT64_MIN; output
//! truncates to 511 bytes plus NUL, without XML escaping the key.

use crate::app::output_buffer_reset::OutputBufferState;
use crate::app::output_buffer_write_dictionary_close::{
    OUTPUT_BUFFER_APPEND_C_STRING, OUTPUT_BUFFER_WRITE_INDENTATION,
};

unsafe fn render(destination: *mut u8, indentation: *const u8, key: *const u8, value: i64) {
    let mut digits = [0u8; 20];
    let mut first = digits.len();
    let mut magnitude = value.unsigned_abs();
    loop {
        first -= 1;
        digits[first] = b'0' + (magnitude % 10) as u8;
        magnitude /= 10;
        if magnitude == 0 { break; }
    }
    if value < 0 {
        first -= 1;
        digits[first] = b'-';
    }
    let mut written = 0usize;
    for part in [indentation, b"<key>\0".as_ptr(), key, b"</key>\n\0".as_ptr(),
                 indentation, b"<integer>\0".as_ptr()] {
        let mut source = part;
        while source.read() != 0 {
            if written < 511 {
                destination.add(written).write_volatile(source.read());
                written += 1;
            }
            source = source.add(1);
        }
    }
    for part in [&digits[first..], b"</integer>\n".as_slice()] {
        for &byte in part {
            if written < 511 {
                destination.add(written).write_volatile(byte);
                written += 1;
            }
        }
    }
    destination.add(written).write_volatile(0);
}

/// Emit a keyed signed 64-bit integer, preserving the retail AAPCS signature.
///
/// # Safety
/// State has the retail layout, 512 writable bytes at +0x15 and sufficient
/// indentation storage at +0x215 for level. Key is a non-null readable C
/// string, disjoint from the scratch. Installed seams obey retail contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn output_buffer_write_keyed_i64(
    state: *mut OutputBufferState, key: *const u8, value: i64, level: u32,
) {
    let indent = core::ptr::addr_of!(OUTPUT_BUFFER_WRITE_INDENTATION).read_volatile();
    indent(state, level);
    let scratch = (state as *mut u8).add(0x15);
    render(scratch, scratch.add(0x200), key, value);
    let append = core::ptr::addr_of!(OUTPUT_BUFFER_APPEND_C_STRING).read_volatile();
    append(state, scratch);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn signed_boundaries_keys_and_truncation() {
        for value in [i64::MIN, i64::MIN + 1, -4294967296, -10, -1, 0, 9, 10,
                      4294967296, i64::MAX] {
            for indent in ["", "\t\t"] {
                for length in [0, 1, 150, 155, 160, 165, 170, 450, 470, 480, 490, 500, 510, 511, 512, 600] {
                    let key = std::format!("{}\0", "<&>".repeat(length));
                    let indentation = std::format!("{indent}\0");
                    let expected = std::format!("{indent}<key>{}</key>\n{indent}<integer>{value}</integer>\n",
                        &key[..key.len() - 1]);
                    let mut output = [0xa5; 514];
                    unsafe { render(output.as_mut_ptr().add(1), indentation.as_ptr(), key.as_ptr(), value); }
                    let used = expected.len().min(511);
                    assert_eq!(&output[1..1 + used], &expected.as_bytes()[..used]);
                    assert_eq!(output[1 + used], 0);
                    assert!(output[used + 2..].iter().all(|&byte| byte == 0xa5));
                    assert_eq!(output[0], 0xa5);
                }
            }
        }
    }
}
