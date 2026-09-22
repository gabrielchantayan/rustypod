//! `media_player_query_index_select` — original: `FUN_081feac4` @
//! **0x081feac4** (**180 bytes**, exactly `0x081feac4..0x081feb78`; the
//! next separately linked function begins at `0x081feb78`).
//!
//! # Algorithm
//!
//! Creates a mode-zero query object and invokes its vtable `+0x1e4` limit
//! slot. A requested index at or above that limit returns 4. Otherwise it
//! reads the media-player interface's current index from vtable `+0x80`,
//! clears registration slot 6 when `register_callback` is zero, or registers
//! `{callback_kind, current_index, 0}` there otherwise, then invokes vtable
//! `+0x7c` only if the current index differs from the requested index. The
//! query object is released through its vtable `+0x1c` on both paths.
//!
//! Raw-word decoding finds five unconditional direct `bl` instructions
//! (`query_object_create`, `media_player_interface_get`, `slot_table_register`,
//! `slot_table_clear`, and `query_object_release_slot`), no predicated direct
//! `bl`, two unconditional dynamic `blx` calls, and one predicated dynamic
//! `blxne` call. The three dynamic targets are runtime vtable data.
//!
//! # Deliberate deviations
//!
//! Retail vtables contain 32-bit function words. Host fixtures use native-width
//! pointers through one aggregate seam; target builds call the already ported
//! query creation/release and media-player singleton functions directly.
//! Rust emits a normal conditional branch around the setter rather than
//! retail's predicated `blxne`; the call condition and arguments are unchanged.

use crate::app::slot_table::{slot_table_clear, slot_table_register};

const SLOT: i32 = 6;
const MEDIA_SET_INDEX_WORD: usize = 0x7c / 4;
const MEDIA_CURRENT_INDEX_WORD: usize = 0x80 / 4;
const QUERY_INDEX_LIMIT_WORD: usize = 0x1e4 / 4;

type QueryIndexLimit = unsafe extern "C" fn(*mut u8) -> u32;
type MediaCurrentIndex = unsafe extern "C" fn(*mut u8) -> u32;
type MediaSetIndex = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
unsafe fn query_index_limit(query: *mut u8) -> u32 {
    let vtable = unsafe { (query as *const *const u32).read() };
    let function: QueryIndexLimit = unsafe { core::mem::transmute((*vtable.add(QUERY_INDEX_LIMIT_WORD)) as usize) };
    unsafe { function(query) }
}

#[cfg(target_os = "none")]
unsafe fn media_current_index(interface: *mut u8) -> u32 {
    let vtable = unsafe { (interface as *const *const u32).read() };
    let function: MediaCurrentIndex = unsafe { core::mem::transmute((*vtable.add(MEDIA_CURRENT_INDEX_WORD)) as usize) };
    unsafe { function(interface) }
}

#[cfg(target_os = "none")]
unsafe fn media_set_index(interface: *mut u8, index: u32) {
    let vtable = unsafe { (interface as *const *const u32).read() };
    let function: MediaSetIndex = unsafe { core::mem::transmute((*vtable.add(MEDIA_SET_INDEX_WORD)) as usize) };
    unsafe { function(interface, index) }
}

#[cfg(target_os = "none")]
unsafe fn select_ops() -> QueryIndexSelectionOps {
    QueryIndexSelectionOps {
        create_query: crate::util::inner_state::query_object_create,
        release_query: crate::util::query_object_release::query_object_release_slot,
        get_interface: super::singletons::media_player_interface_get,
    }
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostQueryIndexVtable {
    pub index_limit: QueryIndexLimit,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostQueryIndexObject {
    pub vtable: *const HostQueryIndexVtable,
    pub limit: u32,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostMediaQueryIndexVtable {
    pub set_index: MediaSetIndex,
    pub current_index: MediaCurrentIndex,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostMediaQueryIndexInterface {
    pub vtable: *const HostMediaQueryIndexVtable,
    pub current: u32,
}

/// Host replacement for the three already-ported dependency entry points.
#[derive(Clone, Copy)]
pub struct QueryIndexSelectionOps {
    pub create_query: unsafe extern "C" fn(u32) -> *mut u8,
    pub release_query: unsafe extern "C" fn(*mut *mut u8) -> *mut *mut u8,
    pub get_interface: unsafe extern "C" fn() -> *mut u8,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_query(_mode: u32) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(slot: *mut *mut u8) -> *mut *mut u8 { slot }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_interface() -> *mut u8 { core::ptr::null_mut() }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_QUERY_INDEX_SELECTION_OPS: QueryIndexSelectionOps = QueryIndexSelectionOps {
    create_query: missing_query, release_query: missing_release, get_interface: missing_interface,
};

#[cfg(not(target_os = "none"))]
pub static mut QUERY_INDEX_SELECTION_OPS: QueryIndexSelectionOps = DEFAULT_QUERY_INDEX_SELECTION_OPS;

#[cfg(not(target_os = "none"))]
unsafe fn select_ops() -> QueryIndexSelectionOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(QUERY_INDEX_SELECTION_OPS)) }
}

#[cfg(not(target_os = "none"))]
unsafe fn query_index_limit(query: *mut u8) -> u32 {
    unsafe { ((*(*(query as *const HostQueryIndexObject)).vtable).index_limit)(query) }
}

#[cfg(not(target_os = "none"))]
unsafe fn media_current_index(interface: *mut u8) -> u32 {
    unsafe { ((*(*(interface as *const HostMediaQueryIndexInterface)).vtable).current_index)(interface) }
}

#[cfg(not(target_os = "none"))]
unsafe fn media_set_index(interface: *mut u8, index: u32) {
    unsafe { ((*(*(interface as *const HostMediaQueryIndexInterface)).vtable).set_index)(interface, index) }
}

/// Selects `requested_index` when it is within the mode-zero query's limit.
///
/// # Safety
/// On target, the query object and media-player interface must expose the
/// recovered vtable entries. `this` is forwarded only to the slot-table calls.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn media_player_query_index_select(
    this: *mut u8, requested_index: u32, register_callback: i32, callback_kind: i32,
) -> u32 {
    let ops = unsafe { select_ops() };
    let mut query = unsafe { (ops.create_query)(0) };
    let limit = unsafe { query_index_limit(query) };
    let result = if requested_index >= limit {
        4
    } else {
        let interface = unsafe { (ops.get_interface)() };
        let current_index = unsafe { media_current_index(interface) };
        if register_callback == 0 {
            unsafe { slot_table_clear(this, SLOT) };
        } else {
            unsafe { slot_table_register(this, SLOT, callback_kind, current_index, 0) };
        }
        if current_index != requested_index {
            unsafe { media_set_index(interface, requested_index) };
        }
        0
    };
    unsafe { (ops.release_query)(&mut query) };
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::slot_table::{Slot, SLOT_KIND_FREE, SLOTS};
    use core::ptr;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut QUERY: *mut u8 = ptr::null_mut();
    static mut INTERFACE: *mut u8 = ptr::null_mut();
    static mut RELEASES: u32 = 0;
    static mut SETS: std::vec::Vec<u32> = std::vec::Vec::new();

    unsafe extern "C" fn create_query(mode: u32) -> *mut u8 { assert_eq!(mode, 0); unsafe { QUERY } }
    unsafe extern "C" fn release_query(slot: *mut *mut u8) -> *mut *mut u8 { unsafe { RELEASES += 1 }; slot }
    unsafe extern "C" fn get_interface() -> *mut u8 { unsafe { INTERFACE } }
    unsafe extern "C" fn index_limit(query: *mut u8) -> u32 {
        unsafe { (*(query as *const HostQueryIndexObject)).limit }
    }
    unsafe extern "C" fn current_index(interface: *mut u8) -> u32 {
        unsafe { (*(interface as *const HostMediaQueryIndexInterface)).current }
    }
    unsafe extern "C" fn set_index(_interface: *mut u8, index: u32) { unsafe { SETS.push(index) } }

    static QUERY_VTABLE: HostQueryIndexVtable = HostQueryIndexVtable { index_limit };
    static MEDIA_VTABLE: HostMediaQueryIndexVtable = HostMediaQueryIndexVtable { set_index, current_index };

    unsafe fn reset_slot() {
        let slot = (ptr::addr_of_mut!(SLOTS) as *mut Slot).add(SLOT as usize);
        ptr::write(slot, Slot { occupied: 0, reserved: [0; 3], kind: SLOT_KIND_FREE, value_a: 0, value_b: 0 });
    }

    #[test]
    fn out_of_range_releases_query_without_media_or_slot_access() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(QUERY_INDEX_SELECTION_OPS)) };
        let mut query = HostQueryIndexObject { vtable: &QUERY_VTABLE, limit: 3 };
        unsafe {
            QUERY = (&mut query as *mut HostQueryIndexObject).cast();
            RELEASES = 0;
            QUERY_INDEX_SELECTION_OPS = QueryIndexSelectionOps { create_query, release_query, get_interface };
            assert_eq!(media_player_query_index_select(ptr::null_mut(), 3, 2, 0), 4);
            assert_eq!(RELEASES, 1);
            QUERY_INDEX_SELECTION_OPS = previous;
        }
    }

    #[test]
    fn valid_selection_registers_previous_index_and_sets_only_when_changed() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = unsafe { ptr::read_volatile(ptr::addr_of!(QUERY_INDEX_SELECTION_OPS)) };
        let mut query = HostQueryIndexObject { vtable: &QUERY_VTABLE, limit: 5 };
        let mut media = HostMediaQueryIndexInterface { vtable: &MEDIA_VTABLE, current: 1 };
        unsafe {
            QUERY = (&mut query as *mut HostQueryIndexObject).cast();
            INTERFACE = (&mut media as *mut HostMediaQueryIndexInterface).cast();
            RELEASES = 0; SETS.clear(); reset_slot();
            QUERY_INDEX_SELECTION_OPS = QueryIndexSelectionOps { create_query, release_query, get_interface };
            assert_eq!(media_player_query_index_select(ptr::null_mut(), 4, 1, 2), 0);
            let slot = &*(ptr::addr_of!(SLOTS) as *const Slot).add(SLOT as usize);
            assert_eq!((slot.occupied, slot.kind, slot.value_a, slot.value_b), (1, 2, 1, 0));
            assert_eq!(SETS.as_slice(), &[4]);
            assert_eq!(RELEASES, 1);
            assert_eq!(media_player_query_index_select(ptr::null_mut(), 1, 0, 0), 0);
            assert_eq!(SETS.as_slice(), &[4]);
            assert_eq!((slot.occupied, slot.kind, slot.value_a, slot.value_b), (0, SLOT_KIND_FREE, 0, 0));
            QUERY_INDEX_SELECTION_OPS = previous;
        }
    }
}
