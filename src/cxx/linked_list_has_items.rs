//! Checks whether an intrusive linked list contains an item — `FUN_0839eb18` @
//! 0x0839eb18.
//!
//! Raw `osos.dec` establishes the 52-byte extent 0x0839eb18..0x0839eb4c:
//! thirteen ARM words from `push {r4,r5,r6,lr}` through `pop {r4,r5,r6,pc}`;
//! the independent store-and-return helper at 0x0839eb4c follows immediately.
//! It has three direct, unconditional `bl` calls and no predicated calls.
//!
//! Algorithm: call the unported entry wrapper on the embedded guard at +8,
//! count the null-terminated intrusive chain whose head is the target-width
//! word at +0, then call the paired exit wrapper on that same guard. A zero
//! count returns zero; otherwise the exit wrapper's r0 residue is returned.
//! The wrappers tail-branch to 0x08056510 and 0x08056710 respectively; their
//! concrete identities remain unrecovered, so this port preserves fixed-address
//! calls rather than inventing callee names.
//!
//! Deliberate deviation: the list head and node links remain `u32` target
//! addresses on every build. Host tests map a below-4-GiB slab for this layout.

const GUARD_OFFSET: usize = 8;
const RETAIL_GUARD_ENTER: usize = 0x0807_f5c4;
const RETAIL_LIST_ITEM_COUNT: usize = 0x0807_a13c;
const RETAIL_GUARD_EXIT: usize = 0x0807_f6a0;

type GuardCall = unsafe extern "C" fn(*mut u8) -> usize;
type ListItemCount = unsafe extern "C" fn(*mut u8) -> u32;

#[cfg(not(target_os = "none"))]
pub struct LinkedListHasItemsOps {
    pub enter: GuardCall,
    pub count: ListItemCount,
    pub exit: GuardCall,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_guard_call(_guard: *mut u8) -> usize {
    panic!("linked_list_has_items guard wrapper was not installed")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_item_count(_list: *mut u8) -> u32 {
    panic!("linked_list_has_items count helper was not installed")
}

#[cfg(not(target_os = "none"))]
pub static mut LINKED_LIST_HAS_ITEMS_OPS: LinkedListHasItemsOps = LinkedListHasItemsOps {
    enter: missing_guard_call,
    count: missing_list_item_count,
    exit: missing_guard_call,
};

#[inline(always)]
unsafe fn guard_enter(guard: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let call: GuardCall = unsafe { core::mem::transmute(RETAIL_GUARD_ENTER) };
        unsafe { call(guard) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let call = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LINKED_LIST_HAS_ITEMS_OPS.enter)) };
        unsafe { call(guard) };
    }
}

#[inline(always)]
unsafe fn list_item_count(list: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    {
        let call: ListItemCount = unsafe { core::mem::transmute(RETAIL_LIST_ITEM_COUNT) };
        return unsafe { call(list) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let call = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LINKED_LIST_HAS_ITEMS_OPS.count)) };
        unsafe { call(list) }
    }
}

#[inline(always)]
unsafe fn guard_exit(guard: *mut u8) -> usize {
    #[cfg(target_os = "none")]
    {
        let call: GuardCall = unsafe { core::mem::transmute(RETAIL_GUARD_EXIT) };
        return unsafe { call(guard) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let call = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(LINKED_LIST_HAS_ITEMS_OPS.exit)) };
        unsafe { call(guard) }
    }
}

/// Returns zero for an empty chain, otherwise the paired guard-exit return.
///
/// # Safety
/// `list` must point to the retail layout: an intrusive-head `u32` at +0 and
/// a guard object at +8. Each nonzero link must name a readable node whose
/// first target-width word is its successor.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn linked_list_has_items(list: *mut u8) -> usize {
    let guard = unsafe { list.add(GUARD_OFFSET) };
    unsafe { guard_enter(guard) };
    let count = unsafe { list_item_count(list) };
    let exit_result = unsafe { guard_exit(guard) };
    if count == 0 { 0 } else { exit_result }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};

    const FIXTURE_LEN: usize = 0x1000;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::LINKED_LIST_HAS_ITEMS, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [usize; 3] = [0; 3];
    static mut GUARDED_LIST: [usize; 3] = [0; 3];
    static mut ITEM_COUNT: u32 = 0;

    unsafe extern "C" fn enter(guard: *mut u8) -> usize {
        unsafe {
            CALLS[0] += 1;
            GUARDED_LIST[0] = guard as usize;
        }
        0xaaaa
    }

    unsafe extern "C" fn count(list: *mut u8) -> u32 {
        unsafe {
            CALLS[1] += 1;
            GUARDED_LIST[1] = list as usize;
            ITEM_COUNT
        }
    }

    unsafe extern "C" fn exit(guard: *mut u8) -> usize {
        unsafe {
            CALLS[2] += 1;
            GUARDED_LIST[2] = guard as usize;
        }
        0x1234_5678
    }

    fn fixture() -> Option<*mut u8> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe { core::ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some(base)
    }

    fn install_ops(item_count: u32) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            LINKED_LIST_HAS_ITEMS_OPS = LinkedListHasItemsOps { enter, count, exit };
            CALLS = [0; 3];
            GUARDED_LIST = [0; 3];
            ITEM_COUNT = item_count;
        }
        guard
    }

    #[test]
    fn empty_list_enters_counts_and_exits_but_returns_zero() {
        let _lock = install_ops(0);
        let Some(list) = fixture() else {
            note_missing_u32_fixture("cxx::linked_list_has_items");
            return;
        };

        assert_eq!(unsafe { linked_list_has_items(list) }, 0);
        assert_eq!(unsafe { CALLS }, [1, 1, 1]);
        assert_eq!(unsafe { GUARDED_LIST }, [list as usize + GUARD_OFFSET, list as usize, list as usize + GUARD_OFFSET]);
    }

    #[test]
    fn nonempty_list_preserves_guard_exit_return() {
        let _lock = install_ops(2);
        let Some(list) = fixture() else {
            note_missing_u32_fixture("cxx::linked_list_has_items");
            return;
        };

        assert_eq!(unsafe { linked_list_has_items(list) }, 0x1234_5678);
        assert_eq!(unsafe { CALLS }, [1, 1, 1]);
        assert_eq!(unsafe { GUARDED_LIST }, [list as usize + GUARD_OFFSET, list as usize, list as usize + GUARD_OFFSET]);
    }
}
