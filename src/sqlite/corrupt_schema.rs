//! Build a malformed-schema diagnostic and latch `SQLITE_CORRUPT`.
//!
//! - `sqlite_corrupt_schema` — original: `FUN_082c4f7c` @ `0x082c4f7c`
//!   (100 bytes; 4 direct `bl` call sites: all unconditional, no predicated
//!   calls, binary-scanned).
//!
//! Algorithm: unless `db->mallocFailed` (byte +0x1e) is set, replace the
//! caller's error string (+0x08) with `"malformed database schema (" + object
//! (or `"?"`) + `")"`, optionally followed by `" - " + detail`. Then always
//! store `SQLITE_CORRUPT` (11) at +0x0c.
//!
//! Deliberate deviations: the retail `InitData` has target-width pointer
//! words. This port uses word indices, rather than a host-width struct, so the
//! +0x08 error slot and +0x0c status word retain their ARM layout on hosts.

use crate::sqlite::error_msg::VaList;
use crate::sqlite::set_string::sqlite3_set_string;

const SQLITE_CORRUPT: u32 = 11;

#[cfg(test)]
static mut TEST_LITERALS: *const u8 = core::ptr::null();

#[inline(always)]
unsafe fn literal(offset: usize) -> *const u8 {
    #[cfg(test)]
    {
        return core::ptr::read_volatile(core::ptr::addr_of!(TEST_LITERALS)).add(offset);
    }
    #[cfg(not(test))]
    {
        const LITERALS: &[u8] = b"malformed database schema (\0?\0)\0 - \0";
        LITERALS.as_ptr().add(offset)
    }
}

const MALFORMED_SCHEMA_OFFSET: usize = 0;
const UNKNOWN_OBJECT_OFFSET: usize = 27;
const CLOSE_PAREN_OFFSET: usize = 29;
const DETAIL_SEPARATOR_OFFSET: usize = 31;

/// sqlite_corrupt_schema — original: `FUN_082c4f7c` @ `0x082c4f7c` (100
/// bytes; 4 unconditional direct `bl` call sites, no predicated calls).
///
/// `init_data` holds 32-bit target words: db at word 0, error-string slot at
/// word 2, and result code at word 3. `object` and `detail` are nullable
/// NUL-terminated strings. The detail separator is omitted for NULL or empty
/// detail, precisely matching the two conditional ARM instructions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_corrupt_schema(
    init_data: *mut u32,
    object: *const u8,
    detail: *const u8,
) {
    let db = init_data.read() as usize as *const u8;
    if db.add(0x1e).read() == 0 {
        let object = if object.is_null() { literal(UNKNOWN_OBJECT_OFFSET) } else { object };
        let separator = if detail.is_null() || detail.read() == 0 {
            core::ptr::null()
        } else {
            literal(DETAIL_SEPARATOR_OFFSET)
        };
        let args = [
            literal(MALFORMED_SCHEMA_OFFSET) as usize as u32,
            object as usize as u32,
            literal(CLOSE_PAREN_OFFSET) as usize as u32,
            separator as usize as u32,
            detail as usize as u32,
            0,
        ];
        sqlite3_set_string(init_data.add(2).cast::<*mut u8>(), args.as_ptr() as VaList);
    }
    init_data.add(3).write(SQLITE_CORRUPT);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::testing::{hints, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;

    unsafe fn fixture() -> Option<*mut u8> {
        let result = try_map_u32_slab(hints::CORRUPT_SCHEMA, SLAB_LEN)?;
        let literals = result.add(0x500);
        core::ptr::copy_nonoverlapping(b"malformed database schema (\0?\0)\0 - \0".as_ptr(), literals, 35);
        core::ptr::write_volatile(core::ptr::addr_of_mut!(TEST_LITERALS), literals);
        Some(result)
    }

    #[test]
    fn formats_object_and_nonempty_detail_then_latches_corruption() {
        let Some(slab) = (unsafe { fixture() }) else { return };
        unsafe {
            slab.write_bytes(0, SLAB_LEN);
            let db = slab.add(0x100);
            let init = slab.add(0x200).cast::<u32>();
            let object = slab.add(0x300);
            let detail = slab.add(0x320);
            let result = slab.add(0x400);
            core::ptr::copy_nonoverlapping(b"tracks\0".as_ptr(), object, 7);
            core::ptr::copy_nonoverlapping(b"bad root\0".as_ptr(), detail, 9);
            init.write(db as usize as u32);
            let _guard = install_recorder(result);
            sqlite_corrupt_schema(init, object, detail);
            assert_eq!(realloc_log(), std::vec![(0, 48)]);
            assert_eq!(&*core::ptr::slice_from_raw_parts(result, 47), b"malformed database schema (tracks) - bad root\0");
            assert_eq!(init.add(3).read(), SQLITE_CORRUPT);
        }
    }

    #[test]
    fn null_object_and_empty_detail_omit_separator() {
        let Some(slab) = (unsafe { fixture() }) else { return };
        unsafe {
            slab.write_bytes(0, SLAB_LEN);
            let db = slab.add(0x100);
            let init = slab.add(0x200).cast::<u32>();
            let detail = slab.add(0x320);
            let result = slab.add(0x400);
            detail.write(0);
            init.write(db as usize as u32);
            let _guard = install_recorder(result);
            sqlite_corrupt_schema(init, core::ptr::null(), detail);
            assert_eq!(&*core::ptr::slice_from_raw_parts(result, 29), b"malformed database schema (?)\0");
            assert_eq!(init.add(3).read(), SQLITE_CORRUPT);
        }
    }

    #[test]
    fn allocation_failure_still_latches_corruption() {
        let Some(slab) = (unsafe { fixture() }) else { return };
        unsafe {
            slab.write_bytes(0, SLAB_LEN);
            let db = slab.add(0x100);
            let init = slab.add(0x200).cast::<u32>();
            init.write(db as usize as u32);
            let _guard = install_recorder(core::ptr::null_mut());
            sqlite_corrupt_schema(init, core::ptr::null(), core::ptr::null());
            assert_eq!(init.add(2).read(), 0);
            assert_eq!(init.add(3).read(), SQLITE_CORRUPT);
        }
    }
}
