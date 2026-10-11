//! Complete all tasks in the owner's linked 'plst' element.
//!
//! `ui_plst_complete_linked_items` — `FUN_0806460c` @ 0x0806460c.
//! True extent: 80 bytes, including the -65536 literal at 0x08064658;
//! the next function begins at 0x0806465c, before its push at 0x08064664.
//! Raw-word scan: 2 inbound plain BLs (0x08100d70, 0x08189dd8), zero
//! predicated BLs; body: 2 plain BLs, zero predicated BLs.
//!
//! Reload owner+0xf5c every iteration. A null element or zero u16 count
//! at element(+0x40)+0x2e returns zero. Fetch selector 1, forward order,
//! index zero; a null task returns -65536. Otherwise complete the task,
//! ignore its result, and repeat. Both callers discard the return value.
//!
//! Deliberate deviations: expose the status proven by r0 rather than
//! Ghidra's void/two-argument prototype. A volatile ops boundary follows
//! the adjacent completion port; defaults call the existing Rust ports.
//! Volatile owner reads preserve the original repeated loads across callbacks.

use core::ptr;

#[derive(Clone, Copy)]
pub struct PlstCompleteLinkedItemsOps {
    pub item_at: unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32,
    pub complete: unsafe extern "C" fn(*mut u32) -> i32,
}

pub const DEFAULT_PLST_COMPLETE_LINKED_ITEMS_OPS: PlstCompleteLinkedItemsOps =
    PlstCompleteLinkedItemsOps {
        item_at: super::plst_slot_item::ui_plst_slot_item_at,
        complete: super::plst_task_complete::plst_task_complete,
    };
pub static mut PLST_COMPLETE_LINKED_ITEMS_OPS: PlstCompleteLinkedItemsOps =
    DEFAULT_PLST_COMPLETE_LINKED_ITEMS_OPS;

/// # Safety
/// `owner` must be aligned and readable through +0xf5f. Each nonnull link
/// must satisfy the slot-fetch and completion contracts, including an aligned
/// header pointer at +0x40 readable through +0x2f. Callbacks may change the
/// link/count but must leave subsequent reads valid. As in retailOS, a
/// completion that makes no progress can cause an infinite loop.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_plst_complete_linked_items(owner: *mut u8) -> i32 {
    loop {
        let link = owner.add(0xf5c).cast::<u32>();
        if ptr::read_volatile(link) == 0 { return 0; }
        let element = ptr::read_volatile(link) as usize as *mut u8;
        let header = element.add(0x40).cast::<u32>().read() as usize as *const u8;
        if header.add(0x2e).cast::<u16>().read() == 0 { return 0; }
        let ops = ptr::read_volatile(ptr::addr_of!(PLST_COMPLETE_LINKED_ITEMS_OPS));
        let task = (ops.item_at)(element, 1, 0, 0);
        if task == 0 { return -65536; }
        (ops.complete)(task as usize as *mut u32);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        try_map_u32_slab(hints::PLST_COMPLETE_LINKED_ITEMS, 0x5000).map(|p| p as usize)
    });
    static mut OWNER: *mut u8 = ptr::null_mut();
    static mut REMAINING: u16 = 0;
    static mut COMPLETED: u16 = 0;
    static mut FAIL_AT: u16 = u16::MAX;
    static mut REPLACE_LINK: bool = false;
    unsafe extern "C" fn item_at(element: *mut u8, _: u32, _: u32, _: u32) -> u32 {
        if COMPLETED == FAIL_AT { return 0; }
        element as usize as u32
    }
    unsafe extern "C" fn complete(task: *mut u32) -> i32 {
        COMPLETED += 1;
        REMAINING -= 1;
        if REPLACE_LINK {
            OWNER.add(0xf5c).cast::<u32>().write(0);
        } else {
            let header = task.cast::<u8>().add(0x40).cast::<u32>().read() as usize as *mut u8;
            header.add(0x2e).cast::<u16>().write(REMAINING);
        }
        -50 // Must not stop the loop or propagate the completion error.
    }
    struct Restore(PlstCompleteLinkedItemsOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { PLST_COMPLETE_LINKED_ITEMS_OPS = self.0; } }
    }

    #[test]
    fn empty_failure_drain_and_link_replacement() {
        let _lock = LOCK.lock();
        let Some(owner) = SLAB.map(|p| p as *mut u8) else {
            assert!(note_missing_u32_fixture("ui/plst_complete_linked_items")); return;
        };
        unsafe {
            owner.write_bytes(0, 0x5000);
            OWNER = owner;
            let element = owner.add(0x1000);
            let header = owner.add(0x3000);
            element.add(0x40).cast::<u32>().write(header as usize as u32);
            let _restore = Restore(PLST_COMPLETE_LINKED_ITEMS_OPS);
            PLST_COMPLETE_LINKED_ITEMS_OPS = PlstCompleteLinkedItemsOps { item_at, complete };
            assert_eq!(ui_plst_complete_linked_items(owner), 0);
            owner.add(0xf5c).cast::<u32>().write(element as usize as u32);
            assert_eq!(ui_plst_complete_linked_items(owner), 0);
            for (count, fail_at, replace, expected, completed) in [
                (1, 0, false, -65536, 0),
                (3, 1, false, -65536, 1),
                (3, u16::MAX, false, 0, 3),
                (u16::MAX, 0, false, -65536, 0),
                (3, u16::MAX, true, 0, 1),
            ] {
                owner.add(0xf5c).cast::<u32>().write(element as usize as u32);
                header.add(0x2e).cast::<u16>().write(count);
                REMAINING = count; COMPLETED = 0; FAIL_AT = fail_at; REPLACE_LINK = replace;
                assert_eq!(ui_plst_complete_linked_items(owner), expected);
                let actual = COMPLETED;
                assert_eq!(actual, completed);
            }
        }
    }
}
