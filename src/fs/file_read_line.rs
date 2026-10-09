//! Nonblank line reader — `FUN_080eda58` @ 0x080eda58.
//! True extent [0x080eda58, 0x080edb20): 200 bytes, no literal pool.
//! Two inbound plain BLs, zero predicated; outbound: three plain BLs,
//! one BLNE (payload assignment), and one indirect BLX (destination clear).
//! Clears the destination before validating file word +0x18 against -1.
//! Skips leading CR/LF, collects at most 254 bytes, and succeeds on EOF (5),
//! NUL, or a nonempty line delimiter. Other errors and overflow return zero.
//! EOF/NUL precede error and capacity checks; a delimiter at length 254 fails.
//! Deviations: existing typed file/string ports replace direct stock calls;
//! a Rust closure expresses the byte-read loop, with no heap allocation.

use crate::app::string_owner_init::string_owner_embedded_init;
use crate::cxx::string_object::{string_object_assign_payload, string_object_destroy, StringObject};
use crate::fs::file_read::retail_file_read;

fn collect_line(buffer: &mut [core::mem::MaybeUninit<u8>; 256], mut read: impl FnMut(&mut u8) -> i32) -> bool {
    let mut length = 0;
    let mut byte = 0;
    loop {
        let status = read(&mut byte);
        if status == 5 || byte == 0 {
            break;
        }
        if status != 0 || length >= 254 {
            return false;
        }
        if byte == b'\n' || byte == b'\r' {
            if length != 0 { break; }
        } else {
            buffer[length].write(byte);
            length += 1;
        }
    }
    buffer[length].write(0);
    true
}

/// Read the next nonblank line into a StringObject; see module evidence above.
///
/// # Safety
/// `file` must be a retail file object with a readable signed word at +0x18;
/// `destination` must have a callable clear method in vtable slot +0x0c and
/// satisfy the existing StringObject assignment/destruction contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_file_read_line(
    file: *mut core::ffi::c_void,
    destination: *mut StringObject,
) -> u32 {
    let clear: unsafe extern "C" fn(*mut StringObject) =
        core::mem::transmute((*(*destination).vtable).slots[3]);
    clear(destination);
    if file.cast::<u8>().add(0x18).cast::<i32>().read() == -1 {
        return 0;
    }
    let mut buffer = [core::mem::MaybeUninit::<u8>::uninit(); 256];
    let mut transferred = 0u32;
    if !collect_line(&mut buffer, |byte| {
        retail_file_read(file, 1, byte, &mut transferred)
    }) {
        return 0;
    }
    let mut temporary = core::mem::MaybeUninit::<StringObject>::uninit();
    let source = string_owner_embedded_init(temporary.as_mut_ptr(), buffer.as_ptr().cast());
    if destination != source {
        string_object_assign_payload(destination, (*source).payload);
    }
    string_object_destroy(temporary.as_mut_ptr());
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8], terminal: i32, terminal_byte: u8) -> (bool, [u8; 256], usize) {
        let mut buffer = [core::mem::MaybeUninit::new(0xa5); 256];
        let mut consumed = 0;
        let result = collect_line(&mut buffer, |byte| {
            if consumed < bytes.len() {
                *byte = bytes[consumed];
                consumed += 1;
                0
            } else {
                *byte = terminal_byte;
                consumed += 1;
                terminal
            }
        });
        (result, buffer.map(|byte| unsafe { byte.assume_init() }), consumed)
    }

    #[test]
    fn skips_blank_delimiters_and_preserves_high_bytes() {
        let (ok, buffer, consumed) = run(b"\r\n\nA\xff\rrest", 5, 99);
        assert!(ok);
        assert_eq!(&buffer[..4], &[b'A', 255, 0, 0xa5]);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn eof_and_nul_precede_errors_and_capacity() {
        for bytes in [&b""[..], &b"abc"[..], &[b'x'; 254][..]] {
            for (status, byte) in [(5, 99), (2, 0), (0, 0)] {
                let (ok, buffer, consumed) = run(bytes, status, byte);
                assert!(ok);
                assert_eq!(&buffer[..bytes.len()], bytes);
                assert_eq!(buffer[bytes.len()], 0);
                assert_eq!(consumed, bytes.len() + 1);
            }
        }
        assert!(!run(b"abc", 2, b'x').0);
    }

    #[test]
    fn capacity_check_precedes_delimiter_and_rejects_extra_byte() {
        let mut bytes = [b'x'; 255];
        for last in [b'\r', b'\n', b'x'] {
            bytes[254] = last;
            let (ok, _, consumed) = run(&bytes, 5, 0);
            assert!(!ok);
            assert_eq!(consumed, 255);
        }
        bytes[253] = b'\n';
        let (ok, buffer, consumed) = run(&bytes, 5, 0);
        assert!(ok);
        assert_eq!(buffer[253], 0);
        assert_eq!(consumed, 254);
    }

    #[test]
    fn invalid_file_still_clears_destination() {
        unsafe extern "C" fn clear(string: *mut StringObject) {
            (*string).payload = core::ptr::null_mut();
        }
        let vtable = crate::cxx::string_object::StringObjectVtable {
            slots: [0, 0, 0, clear as *const () as usize, 0, 0],
        };
        let mut string = StringObject { vtable: &vtable, payload: 1usize as *mut u8 };
        let mut file = [0i32; 7];
        file[6] = -1;
        assert_eq!(unsafe { retail_file_read_line(file.as_mut_ptr().cast(), &mut string) }, 0);
        assert!(string.payload.is_null());
    }
}
