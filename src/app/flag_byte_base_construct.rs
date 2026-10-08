//! Polymorphic flag-byte base constructor.
//!
//! Original `FUN_081433a4` @ load address `0x081433a4`: true size 32
//! bytes (28 code bytes plus vtable literal at `0x081433c0`); the next
//! real function begins at `0x081433c4`. Raw-word scan verifies two plain
//! incoming BLs (`0x081b9008`, `0x0822515c`), zero predicated incoming BLs,
//! one plain outgoing BL (`0x081433ac` to `framework_object_construct`),
//! and zero predicated outgoing BLs.
//!
//! Construct the framework root, replace its vtable, store the low byte
//! of the flag at +4, and return the root's pointer unchanged. Padding at
//! +5..+7 and all derived fields remain untouched. Class identity and the
//! flag's meaning are unknown; both inspected derived callers pass zero.
//!
//! Deliberate deviations: none. Fixed-width word storage preserves the
//! target layout on hosts; volatile stores retain the root/vtable order.

use crate::cxx::observable_array::framework_object_construct;

pub const FLAG_BYTE_BASE_VTABLE: u32 = 0x0898_5d70;

/// # Safety
/// `storage` must be word-aligned and writable for at least five bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn flag_byte_base_construct(storage: *mut u32, flag: u32) -> *mut u32 {
    let object = framework_object_construct(storage.cast()).cast::<u32>();
    object.write_volatile(FLAG_BYTE_BASE_VTABLE);
    object.cast::<u8>().add(4).write_volatile(flag as u8);
    object
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_flag_preserves_padding_and_derived_storage() {
        for flag in [0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1234_5678, u32::MAX] {
            for fill in [0u32, 0xa5a5_a5a5, u32::MAX] {
                let mut words = [fill; 6];
                let mut expected = words;
                expected[1] = FLAG_BYTE_BASE_VTABLE;
                let mut bytes = expected[2].to_ne_bytes();
                bytes[0] = flag as u8;
                expected[2] = u32::from_ne_bytes(bytes);
                let storage = unsafe { words.as_mut_ptr().add(1) };
                let result = unsafe { flag_byte_base_construct(storage, flag) };
                assert_eq!(result, storage);
                assert_eq!(words, expected, "flag={flag:#x}, fill={fill:#x}");
            }
        }
    }
}
