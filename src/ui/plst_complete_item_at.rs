//! Completes an indexed task in an owner's linked 'plst' element.
//!
//! `ui_plst_complete_item_at` — `FUN_0806465c` @ 0x0806465c, 92 bytes
//! through the -65536 literal at 0x080646b4; next function: 0x080646b8.
//! Raw-word scan verifies 2 inbound plain BLs (0x081a31c8, 0x081a4cac),
//! zero predicated BLs; body: 3 plain BLs, zero predicated BLs.
//!
//! Reject negative or out-of-count indices with -50. Fetch selector 1,
//! forward order, from owner+0xf50; a zero item returns -65536. Complete
//! the task, returning zero on success and -20 for any completion error.
//! The count helper changes only r0/flags, preserving owner in r2 and index
//! in r1: Ghidra's apparent two-word return is not the retail ABI.
//!
//! Deliberate deviation: explicit Rust locals replace the stock reliance on
//! callee-preserved scratch registers. A volatile ops boundary follows the
//! existing completion wrappers; defaults call all three existing Rust ports.

use core::ptr;

#[derive(Clone, Copy)]
pub struct PlstCompleteItemAtOps {
    pub count: unsafe extern "C" fn(*const u8) -> u32,
    pub item_at: unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32,
    pub complete: unsafe extern "C" fn(*mut u32) -> i32,
}

pub const DEFAULT_PLST_COMPLETE_ITEM_AT_OPS: PlstCompleteItemAtOps = PlstCompleteItemAtOps {
    count: super::plst_linked_item_count::ui_plst_linked_item_count,
    item_at: super::plst_slot_item::ui_plst_slot_item_at,
    complete: super::plst_task_complete::plst_task_complete,
};
pub static mut PLST_COMPLETE_ITEM_AT_OPS: PlstCompleteItemAtOps = DEFAULT_PLST_COMPLETE_ITEM_AT_OPS;

/// # Safety
/// For nonnegative indices, `owner` must be aligned and readable through
/// +0xf53, with linked element/header storage satisfying the count port.
/// In-range indices additionally require the slot-fetch and task-completion
/// contracts. Negative indices do not dereference `owner`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_plst_complete_item_at(owner: *mut u8, index: i32) -> i32 {
    if index < 0 { return -50; }
    let ops = ptr::read_volatile(ptr::addr_of!(PLST_COMPLETE_ITEM_AT_OPS));
    if index as u32 >= (ops.count)(owner) { return -50; }
    let element = owner.add(0xf50).cast::<u32>().read() as usize as *mut u8;
    let task = (ops.item_at)(element, 1, 0, index as u32);
    if task == 0 { return -65536; }
    if (ops.complete)(task as usize as *mut u32) == 0 { 0 } else { -20 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        try_map_u32_slab(hints::PLST_COMPLETE_ITEM_AT, 0x3000).map(|base| base as usize)
    });
    static mut ITEM: u32 = 0;
    static mut RESULT: i32 = 0;
    unsafe extern "C" fn item_at(_: *mut u8, _: u32, _: u32, _: u32) -> u32 { ITEM }
    unsafe extern "C" fn complete(_: *mut u32) -> i32 { RESULT }
    struct Restore(PlstCompleteItemAtOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { PLST_COMPLETE_ITEM_AT_OPS = self.0; } }
    }

    #[test]
    fn index_boundaries_and_completion_error_mapping() {
        let _lock = LOCK.lock();
        let Some(base) = SLAB.map(|base| base as *mut u8) else {
            assert!(note_missing_u32_fixture("ui/plst_complete_item_at")); return;
        };
        unsafe {
            base.write_bytes(0, 0x3000);
            let element = base.add(0x1000);
            let header = base.add(0x2000);
            base.add(0xf50).cast::<u32>().write(element as usize as u32);
            element.add(0x40).cast::<u32>().write(header as usize as u32);
            let _restore = Restore(PLST_COMPLETE_ITEM_AT_OPS);
            PLST_COMPLETE_ITEM_AT_OPS = PlstCompleteItemAtOps {
                count: DEFAULT_PLST_COMPLETE_ITEM_AT_OPS.count, item_at, complete,
            };
            for index in [i32::MIN, -1] {
                assert_eq!(ui_plst_complete_item_at(ptr::null_mut(), index), -50);
            }
            ITEM = 1; RESULT = 0;
            assert_eq!(ui_plst_complete_item_at(base, 0), -50);
            header.add(0x2e).cast::<u16>().write(3);
            for index in [3, 4, i32::MAX] {
                assert_eq!(ui_plst_complete_item_at(base, index), -50);
            }
            for index in [0, 2] {
                ITEM = 0;
                assert_eq!(ui_plst_complete_item_at(base, index), -65536);
                ITEM = 1;
                for result in [i32::MIN, -50, -1, 1, i32::MAX, 0] {
                    RESULT = result;
                    assert_eq!(ui_plst_complete_item_at(base, index), if result == 0 { 0 } else { -20 });
                }
            }
            header.add(0x2e).cast::<u16>().write(u16::MAX);
            assert_eq!(ui_plst_complete_item_at(base, 65534), 0);
            assert_eq!(ui_plst_complete_item_at(base, 65535), -50);
            base.add(0xf50).cast::<u32>().write(0);
            assert_eq!(ui_plst_complete_item_at(base, 0), -50);
        }
    }
}
