//! `read_global_passkey` — `FUN_081725a8` @ **0x081725a8**.
//!
//! True extent: 104 bytes, 0x081725a8..0x08172610: 92 instruction bytes,
//! a global-address literal, and eight bytes containing `"0000\0"` and padding.
//! Raw aligned A32 decoding finds two plain outgoing BLs to
//! `string_object_assign_cstr` @ 0x0827639c and zero predicated BLs. There
//! are two plain incoming BLs (0x0827f5e0, 0x0827fbf4), zero predicated.
//!
//! Read the signed state from the global record at 0x08a77114 and publish it.
//! For state -1, clear enabled before assigning `"0000"` and return zero.
//! Otherwise assign the NUL-terminated text at +5, then read the byte at +4,
//! normalize any nonzero value to one, and return one. The receiver is unused.
//! No deliberate behavioral deviations; a private record/assignment parameter
//! makes host fixtures possible without replacing the firmware ABI or callee.

use crate::cxx::string_object::{string_object_assign_cstr, StringObject};

const PASSKEY_RECORD: usize = 0x08a77114;
const DEFAULT_PASSKEY: &[u8; 5] = b"0000\0";

#[inline(always)]
unsafe fn read_record(
    record: *const u32,
    state: *mut i32,
    enabled: *mut u8,
    text: *mut StringObject,
    mut assign: impl FnMut(*mut StringObject, *const u8),
) -> u32 {
    let current = record.read_volatile() as i32;
    state.write(current);
    if current == -1 {
        enabled.write(0);
        assign(text, DEFAULT_PASSKEY.as_ptr());
        0
    } else {
        assign(text, record.cast::<u8>().add(5));
        enabled.write(u8::from(record.cast::<u8>().add(4).read_volatile() != 0));
        1
    }
}

/// # Safety
/// The firmware global must contain an aligned state, flag byte, and terminated
/// text. Output pointers must be writable, and `text` a valid StringObject.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn read_global_passkey(
    _receiver: *mut u8,
    state: *mut i32,
    enabled: *mut u8,
    text: *mut StringObject,
) -> u32 {
    read_record(PASSKEY_RECORD as *const u32, state, enabled, text,
        |destination, source| string_object_assign_cstr(destination, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_uses_default_and_clears_flag_before_assignment() {
        let record = [u32::MAX, 0xffff_ffff, 0xffff_ffff];
        let mut state = 7;
        let mut enabled = 99u8;
        let flag = &mut enabled as *mut u8;
        let mut copied = [0; 5];
        let result = unsafe { read_record(record.as_ptr(), &mut state, flag,
            core::ptr::null_mut(), |_, source| {
                assert_eq!(flag.read(), 0);
                copied.copy_from_slice(core::slice::from_raw_parts(source, 5));
            }) };
        assert_eq!((result, state, enabled), (0, -1, 0));
        assert_eq!(&copied, b"0000\0");
    }

    #[test]
    fn valid_states_copy_text_and_normalize_flag_after_assignment() {
        for state_value in [0i32, 1, -2, i32::MIN, i32::MAX] {
            for flag_value in [0u8, 1, 0x80, 0xff] {
                for text_value in [b"1234\0", b"\0xxx\0"] {
                    let mut record = [state_value as u32, 0, 0];
                    let bytes = record.as_mut_ptr().cast::<u8>();
                    unsafe {
                        bytes.add(4).write(flag_value);
                        core::ptr::copy_nonoverlapping(text_value.as_ptr(), bytes.add(5), 5);
                    }
                    let mut state = 7;
                    let mut enabled = 99;
                    let flag = &mut enabled as *mut u8;
                    let mut copied = [0; 5];
                    let result = unsafe { read_record(record.as_ptr(), &mut state, flag,
                        core::ptr::null_mut(), |_, source| {
                            assert_eq!(flag.read(), 99);
                            copied.copy_from_slice(core::slice::from_raw_parts(source, 5));
                            // The flag must be reloaded after the string callee.
                            bytes.add(4).write(flag_value ^ 0xff);
                        }) };
                    assert_eq!(result, 1);
                    assert_eq!(state, state_value);
                    assert_eq!(enabled, u8::from(flag_value != 0xff));
                    assert_eq!(&copied, text_value);
                }
            }
        }
    }
}
