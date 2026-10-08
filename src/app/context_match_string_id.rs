//! Conditional string identifier for a handle-owned item's context match.
//!
//! Original FUN_08177ce0 @ 0x08177ce0, true extent 76 bytes through
//! 0x08177d2c: 68 code bytes and literals 0x089ca674 / 0x63eb. Raw decoding
//! verifies three outgoing unconditional BLs, zero predicated BLs, and two
//! incoming unconditional BLs (0x08133a38, 0x08174f98). Query the app root;
//! only a zero result permits handle dereference and the indexed item query.
//! Return 0x63eb only for an item-query result exactly equal to one, else zero.
//!
//! Deviations: the item query retains its verified retail entry address and
//! intentionally neutral name, not a guessed class identity. The root query
//! uses the canonical root_media_query_is_zero port. Host builds require a
//! native item query and root provider. ARM reads the literal root slot
//! directly, preserving the firmware's runtime root value.

//! The root query now uses the canonical Rust port rather than the obsolete
//! retail boundary. The item query retains its verified retail address.
use crate::cxx::handle::handle_deref_or_null;
use crate::app::root_media_query_is_zero::root_media_query_is_zero;

type ItemQuery = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_item_query(_: *mut u8, _: u32) -> u32 {
    panic!("install context-match item query (retail 0x0813df7c)")
}
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
    let (root, item_query): (*mut u8, ItemQuery) = (
        (0x089ca674 as *const *mut u8).read(),
        core::mem::transmute(0x0813df7cusize),
    );
    #[cfg(not(target_os = "none"))]
    let (root, item_query) = (
        CONTEXT_MATCH_ROOT(), CONTEXT_MATCH_ITEM_QUERY,
    );
    if root_media_query_is_zero(root) != 0 {
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
    use crate::app::root_media_query_is_zero::{ROOT_MEDIA_QUERY, TEST_LOCK};

    static mut MEDIA_RESULT: u32 = 0;
    static mut ITEM_RESULT: u32 = 0;
    static mut ITEM_CALLS: u32 = 0;
    static mut EXPECTED_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut ROOT: [u32; 13] = [0; 13];
    unsafe fn root() -> *mut u8 { core::ptr::addr_of_mut!(ROOT).cast() }
    unsafe extern "C" fn media_query(_: u32) -> u32 {
        MEDIA_RESULT
    }
    unsafe extern "C" fn item_query(object: *mut u8, index: u32) -> u32 {
        assert_eq!(object, EXPECTED_OBJECT);
        assert_eq!(index, u32::MAX);
        ITEM_CALLS += 1;
        ITEM_RESULT
    }

    #[test]
    fn exact_match_and_short_circuit_boundaries() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let saved = (CONTEXT_MATCH_ROOT, ROOT_MEDIA_QUERY, CONTEXT_MATCH_ITEM_QUERY);
            CONTEXT_MATCH_ROOT = root;
            ROOT_MEDIA_QUERY = media_query;
            CONTEXT_MATCH_ITEM_QUERY = item_query;
            MEDIA_RESULT = 0;
            ITEM_CALLS = 0;
            assert_eq!(context_match_string_id(core::ptr::null(), u32::MAX), 0);
            assert_eq!(ITEM_CALLS, 0);
            MEDIA_RESULT = 1;
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
            (CONTEXT_MATCH_ROOT, ROOT_MEDIA_QUERY, CONTEXT_MATCH_ITEM_QUERY) = saved;
        }
    }
}
