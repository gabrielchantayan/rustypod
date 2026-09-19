//! 'plst' item counted-string application helper.

use core::ptr;

use crate::util::string_pool::{string_pool_store_counted, StringPool};

/// Byte offset of the owner pointer.
const OWNER_OFFSET: usize = 0;
/// Byte offset of the alternate-operation argument.
const ALTERNATE_VALUE_OFFSET: usize = 0x20;
/// Byte offset of the string-pool entry id.
const STRING_ID_OFFSET: usize = 0x28;
/// Owner offsets used by the active path.
const STRING_POOL_OFFSET: usize = 0xcc;
const TAGGED_LIST_OFFSET: usize = 0x48;
/// Literal notification key at 0x08067240. Its semantic identity is unrecovered.
const APPLY_COUNTED_STRING_NOTIFY_TAG: u32 = 0x6370_6c69;

type AlternateApply = unsafe extern "C" fn(u32) -> u32;
type MarkActive = unsafe extern "C" fn(*mut u8);
type TaggedListNotify = unsafe extern "C" fn(*mut u8, u32, *mut u8, *const u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_alternate_apply(value: u32) -> u32 {
    let function: AlternateApply = core::mem::transmute(0x0806_7c48usize);
    function(value)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_alternate_apply(_: u32) -> u32 { 0 }

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_mark_active(element: *mut u8) {
    let function: MarkActive = core::mem::transmute(0x0805_d340usize);
    function(element)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_mark_active(_: *mut u8) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tagged_list_notify(list: *mut u8, tag: u32, context: *mut u8, payload: *const u32, stack_arg: u32) {
    let function: TaggedListNotify = core::mem::transmute(0x0806_6bb8usize);
    function(list, tag, context, payload, stack_arg)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tagged_list_notify(_: *mut u8, _: u32, _: *mut u8, _: *const u32, _: u32) {}

/// Unported boundaries used by [`plst_apply_counted_string`].
#[derive(Clone, Copy)]
pub struct PlstApplyCountedStringOps {
    alternate_apply: AlternateApply,
    mark_active: MarkActive,
    notify: TaggedListNotify,
}

pub const DEFAULT_PLST_APPLY_COUNTED_STRING_OPS: PlstApplyCountedStringOps = PlstApplyCountedStringOps {
    alternate_apply: retail_alternate_apply,
    mark_active: retail_mark_active,
    notify: retail_tagged_list_notify,
};

/// Active dispatch boundary for retail functions 0x08067c48, 0x0805d340, and
/// 0x08066bb8. None has a ported ledger entry.
pub static mut PLST_APPLY_COUNTED_STRING_OPS: PlstApplyCountedStringOps = DEFAULT_PLST_APPLY_COUNTED_STRING_OPS;

#[inline(always)]
unsafe fn ops() -> PlstApplyCountedStringOps {
    ptr::read_volatile(ptr::addr_of!(PLST_APPLY_COUNTED_STRING_OPS))
}

/// plst_apply_counted_string — original: `FUN_080671c4` @ `0x080671c4`
/// (124 bytes including the literal notification key at `0x08067240`).
///
/// Raw ARM spans `push {r4,r5,lr}` at 0x080671c4 through `pop {r4,r5,pc}` at
/// 0x0806723c; the next function begins at 0x08067244, with the literal pool
/// word at 0x08067240. It has four inbound plain `bl` calls and no predicated
/// inbound calls. When flag bit 0 at +0x1d is clear, it invokes 0x08067c48 on
/// the word at +0x20 and returns that status. Otherwise it stores `counted` in
/// the owner's inline pool at +0xcc, writes the id at +0x28, marks the item
/// active, and notifies the owner's list at +0x48 with payload `(1, 0)` and a
/// zero stack argument; notification status is discarded.
///
/// Deliberate deviations: the counted-string wrapper is already ported and is
/// called directly. The three unported callees dispatch through the volatile
/// [`PLST_APPLY_COUNTED_STRING_OPS`] seam; target defaults retain their verified
/// retail addresses. The notification key's semantic identity is not invented.
///
/// # Safety
/// `item` must point to writable fields through +0x2b. Its owner word must be
/// a valid pointer to storage through +0xef on the active path; `counted` is
/// passed to the string-pool wrapper unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plst_apply_counted_string")]
pub unsafe extern "C" fn plst_apply_counted_string(item: *mut u8, counted: *const u16) -> i32 {
    if (*item.add(0x1d) & 1) == 0 {
        return (ops().alternate_apply)(item.add(ALTERNATE_VALUE_OFFSET).cast::<u32>().read()) as i32;
    }

    let owner = item.add(OWNER_OFFSET).cast::<u32>().read() as usize as *mut u8;
    let status = string_pool_store_counted(
        owner.add(STRING_POOL_OFFSET).cast::<StringPool>(),
        counted,
        item.add(STRING_ID_OFFSET).cast::<i32>(),
    );
    (ops().mark_active)(item);
    let payload = [1u32, 0];
    (ops().notify)(owner.add(TAGGED_LIST_OFFSET), APPLY_COUNTED_STRING_NOTIFY_TAG, item, payload.as_ptr(), 0);
    status
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::util::string_pool::{StringPoolStore, STRING_POOL_STORE};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALTERNATE_ARG: u32 = 0;
    static mut ACTIVE_ITEM: usize = 0;
    static mut NOTIFY: (usize, u32, usize, [u32; 2], u32) = (0, 0, 0, [0; 2], 0);
    static mut STORE: (usize, usize, u32, usize) = (0, 0, 0, 0);
    static mut STORE_STATUS: i32 = 0;

    unsafe extern "C" fn alternate(value: u32) -> u32 { ALTERNATE_ARG = value; 0x55 }
    unsafe extern "C" fn active(item: *mut u8) { ACTIVE_ITEM = item as usize; }
    unsafe extern "C" fn notify(list: *mut u8, tag: u32, context: *mut u8, payload: *const u32, stack_arg: u32) {
        NOTIFY = (list as usize, tag, context as usize, [payload.read(), payload.add(1).read()], stack_arg);
    }
    unsafe extern "C" fn store(pool: *mut StringPool, data: *const u8, len: u32, id: *mut i32) -> i32 {
        STORE = (pool as usize, data as usize, len, id as usize); STORE_STATUS
    }

    #[test]
    fn inactive_item_only_uses_alternate_operation() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = try_map_u32_slab(hints::PLST_APPLY_COUNTED_STRING, 0x1000) else { note_missing_u32_fixture("ui::plst_apply_counted_string"); return; };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let item = slab.add(0x400); item.add(ALTERNATE_VALUE_OFFSET).cast::<u32>().write(0x1234_5678);
            let old = PLST_APPLY_COUNTED_STRING_OPS; PLST_APPLY_COUNTED_STRING_OPS = PlstApplyCountedStringOps { alternate_apply: alternate, mark_active: active, notify };
            ALTERNATE_ARG = 0;
            assert_eq!(plst_apply_counted_string(item, ptr::null()), 0x55);
            assert_eq!(ALTERNATE_ARG, 0x1234_5678);
            PLST_APPLY_COUNTED_STRING_OPS = old;
        }
    }

    #[test]
    fn active_item_stores_then_marks_and_notifies_exactly() {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slab) = try_map_u32_slab(hints::PLST_APPLY_COUNTED_STRING, 0x1000) else { note_missing_u32_fixture("ui::plst_apply_counted_string"); return; };
        unsafe {
            ptr::write_bytes(slab, 0, 0x1000);
            let owner = slab; let item = slab.add(0x400); item.cast::<u32>().write(owner as u32); *item.add(0x1d) = 1;
            let old_ops = PLST_APPLY_COUNTED_STRING_OPS; let old_store: StringPoolStore = STRING_POOL_STORE;
            PLST_APPLY_COUNTED_STRING_OPS = PlstApplyCountedStringOps { alternate_apply: alternate, mark_active: active, notify }; STRING_POOL_STORE = store;
            ACTIVE_ITEM = 0; NOTIFY = (0, 0, 0, [0; 2], 0); STORE_STATUS = -7;
            let counted = [2u16, 0x0061, 0x0062];
            assert_eq!(plst_apply_counted_string(item, counted.as_ptr()), -7);
            assert_eq!(STORE, (owner.add(STRING_POOL_OFFSET) as usize, counted.as_ptr() as usize + 2, 4, item.add(STRING_ID_OFFSET) as usize));
            assert_eq!(ACTIVE_ITEM, item as usize);
            assert_eq!(NOTIFY, (owner.add(TAGGED_LIST_OFFSET) as usize, APPLY_COUNTED_STRING_NOTIFY_TAG, item as usize, [1, 0], 0));
            STRING_POOL_STORE = old_store; PLST_APPLY_COUNTED_STRING_OPS = old_ops;
        }
    }
}
