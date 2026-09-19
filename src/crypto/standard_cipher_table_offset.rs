//! Selects the active half of the proprietary cipher's table region.

use crate::crypto::cipher_name::cipher_name_is_standard;

/// standard_cipher_table_offset — original: `FUN_0802de14` @ 0x0802de14
/// (60 bytes, 0x0802de14..0x0802de50, one plain `bl` call to
/// `cipher_name_is_standard` @ 0x0802ddcc; four incoming `bl` call sites).
///
/// Validates `name` against the sole accepted cipher name, `"STANDARD"`. On
/// success, stores `table + 4` when `select_second_half` is zero, or
/// `table + 0x1004` otherwise, and returns one. A rejected name leaves
/// `table_offset_out` untouched and returns zero. The arithmetic wraps at
/// 32 bits, as ARM `add` does.
///
/// Deliberate deviation: this exposes the retailOS Boolean return as `u32`
/// rather than preserving the caller-irrelevant register contents. The name
/// validator is an existing Rust seam for the original single `bl` target.
///
/// # Safety
/// `name` must point to a NUL-terminated byte string. When `name` is the
/// accepted cipher name, `table_offset_out` must be valid for one `u32` write.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn standard_cipher_table_offset(
    select_second_half: u32,
    name: *const u8,
    table: u32,
    table_offset_out: *mut u32,
) -> u32 {
    if cipher_name_is_standard(name) as u32 != 0 {
        return 0;
    }

    let offset = if select_second_half == 0 { 4 } else { 0x1004 };
    table_offset_out.write(table.wrapping_add(offset));
    1
}

#[cfg(test)]
mod tests {
    use super::standard_cipher_table_offset;

    #[test]
    fn accepts_standard_name_and_selects_each_table_half() {
        let name = b"STANDARD\0";
        let mut offset = 0;

        unsafe {
            assert_eq!(standard_cipher_table_offset(0, name.as_ptr(), 0x0800_0000, &mut offset), 1);
        }
        assert_eq!(offset, 0x0800_0004);

        unsafe {
            assert_eq!(standard_cipher_table_offset(7, name.as_ptr(), 0x0800_0000, &mut offset), 1);
        }
        assert_eq!(offset, 0x0800_1004);
    }

    #[test]
    fn rejects_other_names_without_dereferencing_output() {
        unsafe {
            assert_eq!(standard_cipher_table_offset(0, b"OTHER\0".as_ptr(), 0, core::ptr::null_mut()), 0);
        }
    }

    #[test]
    fn preserves_arm_add_wraparound() {
        let mut offset = 0;
        unsafe {
            assert_eq!(standard_cipher_table_offset(1, b"STANDARD\0".as_ptr(), u32::MAX - 3, &mut offset), 1);
        }
        assert_eq!(offset, 0x1000);
    }
}
