//! `synchronized_list_append` — retailOS `FUN_0839e71c` @ `0x0839e71c`
//! (72 bytes, `0x0839e71c..0x0839e763`). The next independently entered
//! function begins at `0x0839e764`. Raw ARM decoding verifies two inbound
//! plain `bl` call sites (0x08211bd0 and 0x08211d20), zero predicated inbound
//! `bl` forms, four outbound plain `bl` instructions, and no predicated
//! outbound `bl` forms; the final mutex release is a tail `b`.
//!
//! Allocates an eight-byte node, stores `value` in its second word, appends it
//! to the target-width head/tail list at `owner + 4`, invokes the unresolved
//! cleanup helper on `owner + 20`, then releases the mutex at `owner + 12`.
//!
//! # Deliberate deviations
//!
//! `FUN_080f1158` and `FUN_080744d8` have no names.yaml identities, so target
//! builds call their verified retail addresses while host tests install ABI
//! seams. Host mutex calls use seams too: the target mutex begins at word 3,
//! an address which need not meet the host `Mutex` alignment. Target pointer
//! fields stay as `u32` word indices; this avoids host pointer-width offsets.

use crate::heap::veneers::operator_new;
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

pub type ListAppend = unsafe extern "C" fn(*mut u32, *mut u32);
pub type NodeAllocate = unsafe extern "C" fn(usize) -> *mut u32;
pub type Cleanup = unsafe extern "C" fn(*mut u32);
pub type MutexOperation = unsafe extern "C" fn(*mut u32);

const RETAIL_LIST_APPEND: usize = 0x080f_1158;
const RETAIL_CLEANUP: usize = 0x0807_44d8;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct SynchronizedListOps {
    pub allocate: NodeAllocate,
    pub append: ListAppend,
    pub cleanup: Cleanup,
    pub lock: MutexOperation,
    pub unlock: MutexOperation,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_: usize) -> *mut u32 {
    panic!("install synchronized-list host operations before appending")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_append(_: *mut u32, _: *mut u32) {
    panic!("install synchronized-list host operations before appending")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cleanup(_: *mut u32) {
    panic!("install synchronized-list host operations before appending")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mutex_operation(_: *mut u32) {
    panic!("install synchronized-list host operations before appending")
}

#[cfg(not(target_os = "none"))]
pub static mut SYNCHRONIZED_LIST_OPS: SynchronizedListOps = SynchronizedListOps {
    allocate: missing_allocate,
    append: missing_append,
    cleanup: missing_cleanup,
    lock: missing_mutex_operation,
    unlock: missing_mutex_operation,
};

#[inline(always)]
unsafe fn allocate_node() -> *mut u32 {
    #[cfg(target_os = "none")]
    {
        return unsafe { operator_new(8).cast() };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SYNCHRONIZED_LIST_OPS.allocate))(8) }
}

#[inline(always)]
unsafe fn append_node(list: *mut u32, node: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let append: ListAppend = unsafe { core::mem::transmute(RETAIL_LIST_APPEND) };
        return unsafe { append(list, node) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SYNCHRONIZED_LIST_OPS.append))(list, node) }
}

#[inline(always)]
unsafe fn cleanup_list(owner: *mut u32) {
    #[cfg(target_os = "none")]
    {
        let cleanup: Cleanup = unsafe { core::mem::transmute(RETAIL_CLEANUP) };
        return unsafe { cleanup(owner) };
    }
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SYNCHRONIZED_LIST_OPS.cleanup))(owner) }
}

#[inline(always)]
unsafe fn lock_mutex(mutex: *mut u32) {
    #[cfg(target_os = "none")]
    return unsafe { mutex_lock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SYNCHRONIZED_LIST_OPS.lock))(mutex) }
}

#[inline(always)]
unsafe fn unlock_mutex(mutex: *mut u32) {
    #[cfg(target_os = "none")]
    return unsafe { mutex_unlock(mutex.cast::<Mutex>()) };
    #[cfg(not(target_os = "none"))]
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SYNCHRONIZED_LIST_OPS.unlock))(mutex) }
}

/// Appends an allocated `value` node while holding the owner's list mutex.
///
/// # Safety
///
/// `owner` must be a writable retailOS object with target-width words through
/// `+20`; allocation, append, and cleanup retain the firmware's unchecked
/// pointer contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.synchronized_list_append")]
pub unsafe extern "C" fn synchronized_list_append(owner: *mut u32, value: u32) {
    unsafe { lock_mutex(owner.add(3)) };
    let node = unsafe { allocate_node() };
    unsafe { node.add(1).write(value) };
    unsafe { append_node(owner.add(1), node) };
    unsafe { cleanup_list(owner.add(5)) };
    unsafe { unlock_mutex(owner.add(3)) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{synchronized_list_append, SynchronizedListOps, SYNCHRONIZED_LIST_OPS};
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const WORDS: usize = 16;
    const NODE: usize = 8;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::SYNCHRONIZED_LIST_APPEND, WORDS * core::mem::size_of::<u32>())
            .map(|pointer| pointer as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());
    static mut NODE_PTR: *mut u32 = core::ptr::null_mut();
    static mut CLEANUP_OWNER: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn allocate(size: usize) -> *mut u32 {
        assert_eq!(size, 8);
        unsafe { NODE_PTR }
    }

    unsafe extern "C" fn append(list: *mut u32, node: *mut u32) {
        unsafe {
            if list.read() == 0 {
                list.write(node as usize as u32);
            } else {
                (list.add(1).read() as usize as *mut u32).write(node as usize as u32);
            }
            list.add(1).write(node as usize as u32);
            node.write(0);
        }
    }

    unsafe extern "C" fn cleanup(owner: *mut u32) {
        unsafe { CLEANUP_OWNER = owner };
    }

    unsafe extern "C" fn mutex_operation(_: *mut u32) {}

    struct OpsReset(SynchronizedListOps);
    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe { SYNCHRONIZED_LIST_OPS = self.0 };
        }
    }

    #[test]
    fn allocates_initializes_appends_and_cleans_up() {
        let _lock = LOCK.lock();
        let Some(base) = (*SLAB).map(|address| address as *mut u32) else { return };
        unsafe {
            base.write(0);
            base.add(1).write(0);
            base.add(2).write(0);
            base.add(NODE).write(0xdead_beef);
            base.add(NODE + 1).write(0);
            NODE_PTR = base.add(NODE);
            CLEANUP_OWNER = core::ptr::null_mut();
            let _reset = OpsReset(SYNCHRONIZED_LIST_OPS);
            SYNCHRONIZED_LIST_OPS = SynchronizedListOps { allocate, append, cleanup, lock: mutex_operation, unlock: mutex_operation };
            synchronized_list_append(base, 0x1234_5678);
            assert_eq!(base.add(1).read(), base.add(NODE) as usize as u32);
            assert_eq!(base.add(2).read(), base.add(NODE) as usize as u32);
            assert_eq!(base.add(NODE).read(), 0);
            assert_eq!(base.add(NODE + 1).read(), 0x1234_5678);
            assert_eq!(CLEANUP_OWNER, base.add(5));
        }
    }

    #[test]
    fn appends_after_the_existing_tail() {
        let _lock = LOCK.lock();
        let Some(base) = (*SLAB).map(|address| address as *mut u32) else { return };
        unsafe {
            let old_tail = base.add(6);
            old_tail.write(0);
            old_tail.add(1).write(0x8765_4321);
            base.add(1).write(old_tail as usize as u32);
            base.add(2).write(old_tail as usize as u32);
            base.add(NODE).write(0xdead_beef);
            base.add(NODE + 1).write(0);
            NODE_PTR = base.add(NODE);
            CLEANUP_OWNER = core::ptr::null_mut();
            let _reset = OpsReset(SYNCHRONIZED_LIST_OPS);
            SYNCHRONIZED_LIST_OPS = SynchronizedListOps { allocate, append, cleanup, lock: mutex_operation, unlock: mutex_operation };
            synchronized_list_append(base, 0x1234_5678);
            assert_eq!(base.add(1).read(), old_tail as usize as u32);
            assert_eq!(base.add(2).read(), base.add(NODE) as usize as u32);
            assert_eq!(old_tail.read(), base.add(NODE) as usize as u32);
            assert_eq!(base.add(NODE).read(), 0);
            assert_eq!(base.add(NODE + 1).read(), 0x1234_5678);
            assert_eq!(CLEANUP_OWNER, base.add(5));
        }
    }
}
