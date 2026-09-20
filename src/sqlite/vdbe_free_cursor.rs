//! Release a VDBE cursor and its owned cursor resources.
//!
//! `vdbe_free_cursor` is retailOS `FUN_0838affc` at load address
//! `0x0838affc`. Raw ARM establishes its 104-byte extent
//! `0x0838affc..0x0838b063`: the final `pop {r4-r6,pc}` is followed by the
//! separately linked `vdbe_get_op` at `0x0838b064`. It has three inbound
//! plain `bl` call sites (`0x082b3944`, `0x082c38c4`, `0x08388ff8`) and no
//! predicated `bl` call sites. Its body has two predicated `bl` instructions
//! (`blne` to `btree_close_cursor` and `sqlite3BtreeClose`) plus one `blx`
//! virtual-table disconnect call.
//!
//! SQLite's `sqlite3VdbeFreeCursor`: close `pCursor`, close `pBt`, then invoke
//! the virtual-table cursor destructor while `p->inVtabMethod` is set. A
//! virtual-table cursor suppresses freeing the containing cursor allocation;
//! otherwise the function tail-calls `tracked_free` on the allocation pointer
//! at cursor `+0x38`. Deliberate deviation: host calls to the two B-tree
//! operations and virtual dispatch use explicit seams; target builds call the
//! verified direct callee or retail address/slot.

use crate::heap::tracked::tracked_free;
use crate::sqlite::btree_close_cursor::btree_close_cursor;
use crate::sqlite::vdbe::Vdbe;

const CURSOR_BTREE: usize = 0x00;
const CURSOR_BTREE_HANDLE: usize = 0x30;
const CURSOR_ALLOCATION: usize = 0x38;
const CURSOR_VTAB: usize = 0x60;
const CURSOR_VTAB_OWNER: usize = 0x64;
const CURSOR_IS_VTAB: usize = 0x1f;
const VDBE_IN_VTAB_METHOD: usize = 0x101;
const VTABLE_DISCONNECT: usize = 0x1c;

type BtreeClose = unsafe extern "C" fn(*mut u8);
type VtabDisconnect = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn close_btree(btree: *mut u8) {
    let close: BtreeClose = unsafe { core::mem::transmute(0x0837_0a20usize) };
    unsafe { close(btree) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_close_cursor(_: *mut u8) {
    panic!("vdbe_free_cursor requires sqlite3BtreeCloseCursor @ 0x08370b40")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_close_btree(_: *mut u8) {
    panic!("vdbe_free_cursor requires sqlite3BtreeClose @ 0x08370a20")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_vtab_disconnect(_: *mut u8, _: *mut u8) {
    panic!("vdbe_free_cursor requires a virtual-table disconnect seam")
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct VdbeFreeCursorOps {
    pub close_cursor: BtreeClose,
    pub close_btree: BtreeClose,
    pub disconnect_vtab: unsafe extern "C" fn(*mut u8, *mut u8),
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_VDBE_FREE_CURSOR_OPS: VdbeFreeCursorOps = VdbeFreeCursorOps {
    close_cursor: missing_close_cursor,
    close_btree: missing_close_btree,
    disconnect_vtab: missing_vtab_disconnect,
};

#[cfg(not(target_os = "none"))]
pub static mut VDBE_FREE_CURSOR_OPS: VdbeFreeCursorOps = DEFAULT_VDBE_FREE_CURSOR_OPS;

#[inline(always)]
unsafe fn word_at(base: *mut u8, offset: usize) -> *mut u8 {
    unsafe { base.add(offset).cast::<u32>().read() as usize as *mut u8 }
}

/// `sqlite3VdbeFreeCursor` — retailOS `FUN_0838affc` @ `0x0838affc` (104 bytes).
///
/// `vdbe` and `cursor` use the target's 32-bit layout. `cursor` may be NULL;
/// every non-NULL pointer slot and virtual method slot read by this function
/// must be valid when its guard permits the corresponding call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_free_cursor(vdbe: *mut Vdbe, cursor: *mut u8) {
    if cursor.is_null() {
        return;
    }

    let btree_cursor = unsafe { word_at(cursor, CURSOR_BTREE) };
    if !btree_cursor.is_null() {
        #[cfg(target_os = "none")]
        unsafe { btree_close_cursor(btree_cursor) };
        #[cfg(not(target_os = "none"))]
        unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(VDBE_FREE_CURSOR_OPS)).close_cursor)(btree_cursor) };
    }

    let btree = unsafe { word_at(cursor, CURSOR_BTREE_HANDLE) };
    if !btree.is_null() {
        #[cfg(target_os = "none")]
        unsafe { close_btree(btree) };
        #[cfg(not(target_os = "none"))]
        unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(VDBE_FREE_CURSOR_OPS)).close_btree)(btree) };
    }

    let vtab_cursor = unsafe { word_at(cursor, CURSOR_VTAB) };
    if !vtab_cursor.is_null() {
        let vtab = unsafe { word_at(cursor, CURSOR_VTAB_OWNER) };
        unsafe { (vdbe.cast::<u8>().add(VDBE_IN_VTAB_METHOD)).write(1) };
        #[cfg(target_os = "none")]
        {
            let disconnect: VtabDisconnect = unsafe { core::mem::transmute(word_at(vtab, VTABLE_DISCONNECT)) };
            unsafe { disconnect(vtab_cursor) };
        }
        #[cfg(not(target_os = "none"))]
        unsafe { (core::ptr::read_volatile(core::ptr::addr_of!(VDBE_FREE_CURSOR_OPS)).disconnect_vtab)(vtab_cursor, vtab) };
        unsafe { (vdbe.cast::<u8>().add(VDBE_IN_VTAB_METHOD)).write(0) };
    }

    if unsafe { cursor.add(CURSOR_IS_VTAB).read() } == 0 {
        unsafe { tracked_free(word_at(cursor, CURSOR_ALLOCATION)) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 3] = [0; 3];

    unsafe extern "C" fn record_close(_: *mut u8) { unsafe { EVENTS[0] = EVENTS[0].wrapping_add(1) } }
    unsafe extern "C" fn record_disconnect(cursor: *mut u8, owner: *mut u8) {
        unsafe { EVENTS[2] = (cursor == 0x1234usize as *mut u8 && owner == 0x5678usize as *mut u8) as u8 }
    }

    #[test]
    fn closes_btree_and_vtab_then_clears_vtab_guard() {
        let Some(slab) = try_map_u32_slab(hints::VDBE_FREE_CURSOR, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_free_cursor"));
            return;
        };
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            slab.write_bytes(0, 0x1000);
            let cursor = slab.add(0x100);
            let vdbe = slab.add(0x300);
            cursor.add(CURSOR_BTREE).cast::<u32>().write(0x1111);
            cursor.add(CURSOR_BTREE_HANDLE).cast::<u32>().write(0x2222);
            cursor.add(CURSOR_VTAB).cast::<u32>().write(0x1234);
            cursor.add(CURSOR_VTAB_OWNER).cast::<u32>().write(0x5678);
            cursor.add(CURSOR_IS_VTAB).write(1);
            EVENTS = [0; 3];
            let saved = VDBE_FREE_CURSOR_OPS;
            VDBE_FREE_CURSOR_OPS = VdbeFreeCursorOps { close_cursor: record_close, close_btree: record_close, disconnect_vtab: record_disconnect };
            vdbe_free_cursor(vdbe.cast(), cursor);
            assert_eq!(EVENTS, [2, 0, 1]);
            assert_eq!(vdbe.add(VDBE_IN_VTAB_METHOD).read(), 0);
            VDBE_FREE_CURSOR_OPS = saved;
        }
    }

    #[test]
    fn null_cursor_is_inert() {
        unsafe { vdbe_free_cursor(core::ptr::null_mut(), core::ptr::null_mut()) };
    }

    #[test]
    fn ordinary_cursor_with_no_allocation_is_released_without_dispatch() {
        let Some(slab) = try_map_u32_slab(hints::VDBE_FREE_CURSOR, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_free_cursor"));
            return;
        };
        let _guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            slab.write_bytes(0, 0x1000);
            vdbe_free_cursor(slab.add(0x300).cast(), slab.add(0x100));
        }
    }
}
