//! `trim_ctype_whitespace` — original: `FUN_0807d814` @ 0x0807d814
//! (136 bytes, 5 plain unconditional `bl` call sites and no predicated forms,
//! verified by decoding osos.dec).
//!
//! Skips leading bytes whose active LC_CTYPE flag has bit 0 set, returns NULL
//! if no bytes remain, then uses the retail unguarded `strlen` to find and NUL
//! terminate trailing flagged bytes. The returned pointer is the first retained
//! byte. The original obtains the ctype-table slot repeatedly while skipping
//! leading bytes and retains the final table pointer for the trailing scan.
//! Deliberate codegen deviation: the ARM LLVM build folds the repeated accessor
//! calls into one libspace+0x24 load; the table slot is process-global in
//! retailOS, so this preserves all observable single-threaded behavior.

/// Removes active-LC_CTYPE whitespace from both ends of a mutable C string.
///
/// Original: `FUN_0807d814` @ 0x0807d814.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn trim_ctype_whitespace(mut text: *mut u8) -> *mut u8 {
    let mut table;
    loop {
        if core::ptr::read_volatile(text) == 0 {
            return core::ptr::null_mut();
        }
        table = core::ptr::read_volatile(crate::runtime::errno::__rt_ctype_table_addr())
            as usize as *const u8;
        if core::ptr::read_volatile(table.add(core::ptr::read_volatile(text) as usize)) & 1 == 0 {
            break;
        }
        text = text.add(1);
    }

    let mut end = text.add(crate::libc::strlen::strlen(text));
    let trailing_start = end;
    while end != text
        && core::ptr::read_volatile(table.add(core::ptr::read_volatile(end.sub(1)) as usize)) & 1 != 0
    {
        end = end.sub(1);
    }
    if end != trailing_start {
        core::ptr::write_volatile(end, 0);
    }
    text
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::errno::__rt_ctype_table_addr;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab, CTYPE_TABLE_TEST_LOCK};
    use core::ptr;
    use std::sync::LazyLock;

    const CTYPE_FIXTURE_LEN: usize = 0x1000;
    static CTYPE_FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::STRING_TRIM_CTYPE, CTYPE_FIXTURE_LEN).map(|pointer| pointer as usize)
    });

    struct CtypeTableRestore {
        slot: *mut u32,
        saved: u32,
    }

    impl Drop for CtypeTableRestore {
        fn drop(&mut self) {
            unsafe { self.slot.write_volatile(self.saved) };
        }
    }

    #[test]
    fn trims_active_table_flags_and_preserves_interior_bytes() {
        let _lock = CTYPE_TABLE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *CTYPE_FIXTURE else {
            assert!(note_missing_u32_fixture("runtime::trim_ctype_whitespace"));
            return;
        };
        unsafe {
            let table = base as *mut u8;
            ptr::write_bytes(table, 0, CTYPE_FIXTURE_LEN);
            for &byte in b" \t\n\r\x0b\x0c_" {
                table.add(byte as usize).write_volatile(1);
            }
            let slot = __rt_ctype_table_addr();
            let _restore = CtypeTableRestore { slot, saved: slot.read_volatile() };
            slot.write_volatile(base as u32);

            for (input, expected_offset, expected) in [
                (&b"\0"[..], None, &b"\0"[..]),
                (&b" \t\n\0"[..], None, &b" \t\n\0"[..]),
                (&b" \tvalue\n \0"[..], Some(2), &b" \tvalue\0"[..]),
                (&b"one two\0"[..], Some(0), &b"one two\0"[..]),
                (&b"_value_\0"[..], Some(1), &b"_value\0"[..]),
            ] {
                let mut actual = [0u8; 16];
                actual[..input.len()].copy_from_slice(input);
                let result = trim_ctype_whitespace(actual.as_mut_ptr());
                assert_eq!(result.is_null(), expected_offset.is_none(), "input {input:?}");
                if let Some(offset) = expected_offset {
                    assert_eq!(result, actual.as_mut_ptr().add(offset), "input {input:?}");
                }
                assert_eq!(&actual[..expected.len()], expected, "input {input:?}");
            }
        }
    }
}
