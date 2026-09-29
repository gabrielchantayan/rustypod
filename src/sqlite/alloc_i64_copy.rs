//! alloc_i64_copy — original: `FUN_082c68ec` @ 0x082c68ec (48 bytes).
//!
//! Raw `osos.dec` words establish the full A32 body at
//! 0x082c68ec..0x082c691c; `push {r4-r6,lr}` at 0x082c691c begins the next
//! function. It has one plain `bl` to `db_malloc_raw` @ 0x08374960 and one
//! predicated `blne` to the IRAM `__rt_memcpy` veneer @ 0x08037db0. The two
//! callers are 0x082c3f7c and 0x082c40f4.
//!
//! Algorithm: load the target-width SQLite connection pointer from `owner`,
//! allocate eight bytes through `sqlite3DbMallocRaw`, and copy the i64 source
//! only when allocation succeeded. Return the allocated pointer in all cases.
//!
//! Deliberate deviations: calls the ported `db_malloc_raw` and `__rt_memcpy`
//! directly rather than their firmware entry points. `owner` is a `*const u32`
//! so its first field remains a four-byte target pointer on 64-bit hosts.

use super::mem::db_malloc_raw;

/// Allocates an eight-byte SQLite-owned copy of `source` using `owner`'s db.
///
/// # Safety
/// `owner` must point to a readable target-width db pointer. When allocation
/// succeeds, `source` must point to eight readable bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.alloc_i64_copy_082c68ec")]
#[inline(never)]
pub unsafe extern "C" fn alloc_i64_copy(owner: *const u32, source: *const u8) -> *mut u8 {
    let db = owner.read() as usize as *mut u8;
    let copy = db_malloc_raw(db, 8);
    if !copy.is_null() {
        crate::libc::rt_memcpy::__rt_memcpy(copy, source, 8);
    }
    copy
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::mem::tests::{install_recorder, realloc_log};
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn allocates_and_copies_all_eight_source_bytes() {
        let Some(owner) = try_map_u32_slab(hints::SQLITE_ALLOC_I64_COPY, 4) else {
            return;
        };
        unsafe { owner.write(0) };
        let source = [0x80, 0x00, 0xff, 0x7f, 0x12, 0x34, 0x56, 0x78];
        let mut allocation = [0xa5; 12];
        let _guard = install_recorder(allocation.as_mut_ptr());

        let copy = unsafe { alloc_i64_copy(owner.cast(), source.as_ptr()) };

        assert_eq!(copy, allocation.as_mut_ptr());
        assert_eq!(&allocation[..8], &source);
        assert!(allocation[8..].iter().all(|&byte| byte == 0xa5));
        assert_eq!(realloc_log(), std::vec![(0, 8)]);
    }

    #[test]
    fn failed_allocation_returns_null_without_reading_source() {
        let Some(owner) = try_map_u32_slab(hints::SQLITE_ALLOC_I64_COPY, 4) else {
            return;
        };
        unsafe { owner.write(0) };
        let _guard = install_recorder(core::ptr::null_mut());

        let copy = unsafe { alloc_i64_copy(owner.cast(), core::ptr::null()) };

        assert!(copy.is_null());
        assert_eq!(realloc_log(), std::vec![(0, 8)]);
    }
}
