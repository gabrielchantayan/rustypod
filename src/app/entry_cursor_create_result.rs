//! Entry result factory, FUN_081a8c98 @ 0x081a8c98.
//! True extent: 92 bytes [0x081a8c98, 0x081a8cf4), followed by an independent
//! push. Raw A32 decoding verifies two inbound plain BLs, four outbound plain
//! BLs, and zero predicated BLs in either direction. Position the cursor by
//! index (ordinal sentinel = UINT_MAX), find the requested key in that index's
//! consecutive entries, then allocate and construct a 28-byte result. Failure
//! to position or find returns NULL without allocating. Kind is read after
//! allocation; the constructor receives the sign-extended low key halfword.
//!
//! Deliberate deviations: reuse operator_new and entry_result_construct.
//! Unported cursor operations retain their verified resident addresses on ARM;
//! host operations are injectable. Cursor layout remains opaque target bytes.
//! Ghidra omitted the live r2 index bound. Entry r3 only seeds scratch storage
//! overwritten by entry_match_index before use in both resident operations;
//! it is not a semantic argument. match.py exits 1: LLVM adds a frame and a
//! resident-address literal, uses BLX for cursor calls, and reuses the known
//! constructor return pointer. Both NULL exits and the four-call path remain.
use crate::app::entry_result_construct::entry_result_construct;
use crate::heap::veneers::operator_new;

#[derive(Clone, Copy)]
pub struct EntryCursorResultOps {
    pub position: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
    pub find: unsafe extern "C" fn(*mut u8, u32) -> *mut u8,
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_position(_: *mut u8, _: u32, _: u32) -> u32 {
    panic!("install resident entry cursor positioning operation")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find(_: *mut u8, _: u32) -> *mut u8 {
    panic!("install resident same-index entry lookup operation")
}
#[cfg(not(target_os = "none"))]
pub static mut ENTRY_CURSOR_RESULT_OPS: EntryCursorResultOps = EntryCursorResultOps {
    position: missing_position, find: missing_find, allocate: operator_new,
};

/// Create a result for `match_key` at `index_bound` using the cursor.
///
/// # Safety
/// Cursor must satisfy the resident positioning/lookup contracts, including a
/// readable kind byte at +8 after allocation. Allocation must supply 28 writable
/// aligned bytes: like stock code, this does not guard a NULL allocation.
/// Host operations must be installed without concurrent mutation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn entry_cursor_create_result(
    cursor: *mut u8, match_key: u32, index_bound: u32,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    let ops = EntryCursorResultOps {
        position: core::mem::transmute(0x081a_8db0usize),
        find: core::mem::transmute(0x081a_8cf4usize),
        allocate: operator_new,
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(ENTRY_CURSOR_RESULT_OPS).read();
    create_result(cursor, match_key, index_bound,
        |cursor, ordinal, bound| (ops.position)(cursor, ordinal, bound),
        |cursor, key| (ops.find)(cursor, key), |size| (ops.allocate)(size))
}

unsafe fn create_result(
    cursor: *mut u8, match_key: u32, index_bound: u32,
    position: impl FnOnce(*mut u8, u32, u32) -> u32,
    find: impl FnOnce(*mut u8, u32) -> *mut u8,
    allocate: impl FnOnce(usize) -> *mut u8,
) -> *mut u8 {
    if position(cursor, u32::MAX, index_bound) == 0 {
        return core::ptr::null_mut();
    }
    let entry = find(cursor, match_key);
    if entry.is_null() {
        return core::ptr::null_mut();
    }
    let result = allocate(28);
    entry_result_construct(result, entry, match_key as i16 as i32 as u32, cursor.add(8).read())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_position_and_absent_entry_do_not_allocate() {
        unsafe {
            assert!(create_result(core::ptr::null_mut(), 7, u32::MAX,
                |_, _, _| 0, |_, _| panic!("lookup after failed positioning"),
                |_| panic!("allocation after failed positioning")).is_null());
            assert!(create_result(core::ptr::null_mut(), 7, 0,
                |_, _, _| 1, |_, _| core::ptr::null_mut(),
                |_| panic!("allocation without matching entry")).is_null());
        }
    }

    #[test]
    fn full_width_lookup_key_and_bound_produce_truncated_result_and_latest_kind() {
        for key in [0, 0x7fff, 0x8000, 0xffff, 0x1234_8001, u32::MAX] {
            for bound in [0, 1, 0x8000_0000, u32::MAX] {
                let mut cursor = [0u32; 8];
                let cursor_ptr = cursor.as_mut_ptr().cast::<u8>();
                let mut result = [0xa5a5_a5a5u32; 7];
                let result_ptr = result.as_mut_ptr().cast::<u8>();
                let entry = 0x1234_5678usize as *mut u8;
                let returned = unsafe {
                    create_result(cursor_ptr, key, bound,
                        |c, ordinal, index| {
                            assert_eq!((c, ordinal, index), (cursor_ptr, u32::MAX, bound));
                            c.add(8).write(0x11);
                            0x8000_0000
                        },
                        |c, requested| { assert_eq!((c, requested), (cursor_ptr, key)); entry },
                        |size| { assert_eq!(size, 28); cursor_ptr.add(8).write(0xfe); result_ptr })
                };
                assert_eq!(returned, result_ptr);
                assert_eq!(result, [0x0898_00cc, 0, 0, 0xa5a5_a500, 0,
                    0x1234_5678, 0xa5fe_0000 | (key & 0xffff)]);
            }
        }
    }
}
