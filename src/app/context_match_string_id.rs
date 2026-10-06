//! Conditional string identifier for a handle-owned item's context match.
//!
//! Original FUN_08177ce0 @ 0x08177ce0, true extent 76 bytes through
//! 0x08177d2c: 68 code bytes and literals 0x089ca674 / 0x63eb. Raw decoding
//! verifies three outgoing unconditional BLs, zero predicated BLs, and two
//! incoming unconditional BLs (0x08133a38, 0x08174f98). Query the app root;
//! only a zero result permits handle dereference and the indexed item query.
//! Return 0x63eb only for an item-query result exactly equal to one, else zero.
//!
//! Deviations: the two unported queries retain verified retail entry addresses
//! and intentionally neutral names, not guessed class identities. Host builds
//! require native query operations and a root provider; the decision logic and
//! existing handle dereference are shared unchanged. ARM reads the literal
//! root slot directly, preserving the firmware's runtime root value.

//! Codegen review: LLVM emits BLX to the two literal retail addresses and a
//! relocatable BL to handle_deref_or_null; the zero-root short circuit and
//! exact-one comparison remain. It synthesizes 0x63eb with MOV/ORR and uses
//! a frame pointer instead of ADS's spare r6 save. Structural diff is expected.
use crate::cxx::handle::handle_deref_or_null;

type RootQuery = unsafe extern "C" fn(*mut u8) -> u32;
type ItemQuery = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_root_query(_: *mut u8) -> u32 {
    panic!("install context-match root query (retail 0x081115f4)")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_item_query(_: *mut u8, _: u32) -> u32 {
    panic!("install context-match item query (retail 0x0813df7c)")
}
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_MATCH_ROOT_QUERY: RootQuery = missing_root_query;
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_MATCH_ITEM_QUERY: ItemQuery = missing_item_query;
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_MATCH_ROOT: unsafe fn() -> *mut u8 =
    crate::app::context_scope::app_root_object;

/// Original 0x08177ce0; 76 bytes, three plain BLs, no predicated BLs.
///
/// # Safety
/// The root and installed query operations must be valid. When the root query
/// returns zero, `item_handle` must be readable in the retail two-level handle
/// layout, and its resolved object must satisfy the item query's contract.
/// A nonzero root result does not access the handle at all.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_match_string_id(
    item_handle: *const *const *mut u8,
    index: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    let (root, root_query, item_query): (*mut u8, RootQuery, ItemQuery) = (
        (0x089ca674 as *const *mut u8).read(),
        core::mem::transmute(0x081115f4usize),
        core::mem::transmute(0x0813df7cusize),
    );
    #[cfg(not(target_os = "none"))]
    let (root, root_query, item_query) = (
        CONTEXT_MATCH_ROOT(), CONTEXT_MATCH_ROOT_QUERY, CONTEXT_MATCH_ITEM_QUERY,
    );
    if root_query(root) != 0 {
        return 0;
    }
    if item_query(handle_deref_or_null(item_handle), index) == 1 {
        0x63eb
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static mut ROOT_RESULT: u32 = 0;
    static mut ITEM_RESULT: u32 = 0;
    static mut ITEM_CALLS: u32 = 0;
    static mut EXPECTED_OBJECT: *mut u8 = core::ptr::null_mut();
    unsafe fn root() -> *mut u8 { 0x1234usize as *mut u8 }
    unsafe extern "C" fn root_query(object: *mut u8) -> u32 {
        assert_eq!(object, 0x1234usize as *mut u8);
        ROOT_RESULT
    }
    unsafe extern "C" fn item_query(object: *mut u8, index: u32) -> u32 {
        assert_eq!(object, EXPECTED_OBJECT);
        assert_eq!(index, u32::MAX);
        ITEM_CALLS += 1;
        ITEM_RESULT
    }

    #[test]
    fn exact_match_and_short_circuit_boundaries() {
        unsafe {
            let saved = (CONTEXT_MATCH_ROOT, CONTEXT_MATCH_ROOT_QUERY, CONTEXT_MATCH_ITEM_QUERY);
            CONTEXT_MATCH_ROOT = root;
            CONTEXT_MATCH_ROOT_QUERY = root_query;
            CONTEXT_MATCH_ITEM_QUERY = item_query;
            for blocked in [1, 2, u32::MAX] {
                ROOT_RESULT = blocked;
                ITEM_CALLS = 0;
                assert_eq!(context_match_string_id(core::ptr::null(), u32::MAX), 0);
                assert_eq!(ITEM_CALLS, 0);
            }
            ROOT_RESULT = 0;
            let mut object = [0u32; 32];
            let object_ptr = object.as_mut_ptr().cast::<u8>();
            let cell = object_ptr;
            let handle_cell = &cell as *const *mut u8;
            for null_cell in [false, true] {
                let handle = if null_cell { core::ptr::null() } else { handle_cell };
                EXPECTED_OBJECT = if null_cell { core::ptr::null_mut() } else { object_ptr };
                for result in [0, 1, 2, 255, 256, u32::MAX] {
                    ITEM_RESULT = result;
                    ITEM_CALLS = 0;
                    assert_eq!(context_match_string_id(&handle, u32::MAX),
                        if result == 1 { 0x63eb } else { 0 });
                    assert_eq!(ITEM_CALLS, 1);
                }
            }
            (CONTEXT_MATCH_ROOT, CONTEXT_MATCH_ROOT_QUERY, CONTEXT_MATCH_ITEM_QUERY) = saved;
        }
    }
}
