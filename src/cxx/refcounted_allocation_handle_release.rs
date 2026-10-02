//! Releases an owned allocation-handle cell.
//!
//! `refcounted_allocation_handle_release` — retailOS `FUN_082803c0` at
//! `0x082803c0` (112 bytes, not Ghidra's reported 108): raw `osos.dec` words
//! run through `pop {r4,r5,r6,pc}` at `0x0828042c`; the next independently
//! entered function starts at `0x08280430`. The body contains four plain
//! direct `bl` instructions (free-wrapper @ `0x080e7970`, unlock veneer @
//! `0x082621ac` twice, and operator-delete @ `0x082aad24`) and no predicated
//! calls. It has four inbound plain `bl` callers.
//!
//! The handle owns a nullable cell at +0x04. A non-NULL cell's first word is a
//! signed reference count. Releasing the final reference frees its optional
//! allocation with tag 43, clears that allocation field, unlocks its mutex,
//! then deletes the cell. Every non-NULL release clears the handle's +0x04 and
//! +0x08 words; a NULL cell leaves the handle untouched.
//!
//! Deliberate deviation: the target's unlock veneer is the already ported
//! `posix_mutex_unlock` body. Host tests use typed operation seams for the
//! three observed external effects; target builds call the ported callees
//! directly.

#[cfg(target_os = "none")]
use crate::heap::veneers::{free_wrapper, operator_delete};
#[cfg(target_os = "none")]
use crate::kernel::posix_mutex::{posix_mutex_unlock, PosixMutex};

/// The heap tag passed to `free_wrapper` for the final allocation.
const ALLOCATION_RELEASE_TAG: usize = 0x2b;

/// Target-layout outer handle. On ARM the cell and cache fields are at +0x04
/// and +0x08; native host pointers intentionally widen only the fixture.
#[repr(C)]
pub struct RefcountedAllocationHandle {
    pub reserved: u32,
    pub cell: *mut RefcountedAllocationCell,
    pub cache: u32,
}

/// The three-word target cell consumed by the release routine.
#[repr(C)]
pub struct RefcountedAllocationCell {
    pub refcount: i32,
    pub allocation: *mut u8,
    #[cfg(target_os = "none")]
    pub mutex: *mut PosixMutex,
    #[cfg(not(target_os = "none"))]
    pub mutex: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(RefcountedAllocationHandle, cell)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 8] = [0; core::mem::offset_of!(RefcountedAllocationHandle, cache)];

#[cfg(not(target_os = "none"))]
pub type AllocationFree = unsafe extern "C" fn(*mut u8, usize);
#[cfg(not(target_os = "none"))]
pub type CellUnlock = unsafe extern "C" fn(*mut u8);
#[cfg(not(target_os = "none"))]
pub type CellDelete = unsafe extern "C" fn(*mut RefcountedAllocationCell);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RefcountedAllocationHandleReleaseOps {
    pub free: AllocationFree,
    pub unlock: CellUnlock,
    pub delete: CellDelete,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free(_: *mut u8, _: usize) { panic!("install release operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_unlock(_: *mut u8) { panic!("install release operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_delete(_: *mut RefcountedAllocationCell) { panic!("install release operations") }

#[cfg(not(target_os = "none"))]
pub static mut REFCOUNTED_ALLOCATION_HANDLE_RELEASE_OPS: RefcountedAllocationHandleReleaseOps =
    RefcountedAllocationHandleReleaseOps { free: missing_free, unlock: missing_unlock, delete: missing_delete };

/// Releases one reference from `handle`'s cell.
///
/// # Safety
/// `handle` must be valid. Its non-NULL cell must be valid; a final release
/// requires valid allocation and mutex objects for the observed callees.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_allocation_handle_release(handle: *mut RefcountedAllocationHandle) {
    let cell = (*handle).cell;
    if cell.is_null() {
        return;
    }

    (*cell).refcount = (*cell).refcount.wrapping_sub(1);
    if (*cell).refcount == 0 {
        let allocation = (*cell).allocation;
        if !allocation.is_null() {
            #[cfg(target_os = "none")]
            free_wrapper(allocation, ALLOCATION_RELEASE_TAG);
            #[cfg(not(target_os = "none"))]
            (core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ALLOCATION_HANDLE_RELEASE_OPS.free)))(allocation, ALLOCATION_RELEASE_TAG);
            (*cell).allocation = core::ptr::null_mut();
        }
        #[cfg(target_os = "none")]
        posix_mutex_unlock((*cell).mutex);
        #[cfg(not(target_os = "none"))]
        (core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ALLOCATION_HANDLE_RELEASE_OPS.unlock)))((*cell).mutex);
        #[cfg(target_os = "none")]
        operator_delete(cell.cast());
        #[cfg(not(target_os = "none"))]
        (core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ALLOCATION_HANDLE_RELEASE_OPS.delete)))(cell);
    } else {
        #[cfg(target_os = "none")]
        posix_mutex_unlock((*cell).mutex);
        #[cfg(not(target_os = "none"))]
        (core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ALLOCATION_HANDLE_RELEASE_OPS.unlock)))((*cell).mutex);
    }

    (*handle).cell = core::ptr::null_mut();
    (*handle).cache = 0;
}

/// Full four-word cell installed by the assignment routine. The release
/// routine consumes only the prefix; the continuation starts at target +12.
#[repr(C)]
pub struct RefcountedAllocationOwnedCell {
    pub prefix: RefcountedAllocationCell,
    pub continuation: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 16] = [0; core::mem::size_of::<RefcountedAllocationOwnedCell>()];

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RefcountedAllocationHandleAssignOps {
    pub lock: unsafe extern "C" fn(*mut u8) -> u32,
    pub allocate: unsafe extern "C" fn(usize) -> *mut RefcountedAllocationOwnedCell,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lock(_: *mut u8) -> u32 { panic!("install assignment operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_: usize) -> *mut RefcountedAllocationOwnedCell { panic!("install assignment operations") }

#[cfg(not(target_os = "none"))]
pub static mut REFCOUNTED_ALLOCATION_HANDLE_ASSIGN_OPS: RefcountedAllocationHandleAssignOps =
    RefcountedAllocationHandleAssignOps { lock: missing_lock, allocate: missing_allocate };

/// Replaces an owned allocation and its mutex.
///
/// Original: `FUN_0828020c` @ `0x0828020c`, 84 bytes through the return
/// at `0x0828025c`; next real entry is `0x08280260`. Verified raw words:
/// three plain BL calls (region_ref_lock, release, operator_new) and one
/// predicated BL (heap_panic); two inbound plain BL callers.
///
/// Locks the old cell's mutex, ignoring lock status, and releases the old
/// reference. Allocates 16 target bytes, installs {1, allocation, mutex, 0},
/// publishes the cell, then caches its allocation word. The old release
/// unlocks the old mutex; the newly supplied mutex is not locked.
///
/// Deliberate deviations: native host pointer fields widen the fixture and
/// allocation size; the cache remains the target's low 32-bit pointer word.
/// Host lock/allocation effects use typed seams, target calls existing ports.
/// Like the firmware, cell initialization precedes the NULL panic check;
/// allocation failure therefore faults before the nominal panic call.
/// LLVM removes that unreachable panic check after the required non-NULL
/// writes. ARM match: 22 instructions versus stock 21; the old-cell lock
/// wrapper is expanded into a conditional mutex call, preserving effects.
///
/// # Safety
/// `handle` and any old cell/mutex must satisfy the release/lock contracts.
/// The allocator must return writable, aligned, non-NULL storage for a full
/// owned cell. `allocation` and `mutex` transfer into the new cell.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_allocation_handle_assign(
    handle: *mut RefcountedAllocationHandle,
    allocation: *mut u8,
    #[cfg(target_os = "none")] mutex: *mut PosixMutex,
    #[cfg(not(target_os = "none"))] mutex: *mut u8,
) {
    let old = (*handle).cell;
    if !old.is_null() {
        #[cfg(target_os = "none")]
        { crate::kernel::posix_mutex::posix_mutex_lock((*old).mutex); }
        #[cfg(not(target_os = "none"))]
        { (core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ALLOCATION_HANDLE_ASSIGN_OPS.lock)))((*old).mutex); }
    }
    refcounted_allocation_handle_release(handle);
    #[cfg(target_os = "none")]
    let cell = crate::heap::veneers::operator_new(16).cast::<RefcountedAllocationOwnedCell>();
    #[cfg(not(target_os = "none"))]
    let cell = (core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_ALLOCATION_HANDLE_ASSIGN_OPS.allocate)))(
        core::mem::size_of::<RefcountedAllocationOwnedCell>());
    core::ptr::addr_of_mut!((*cell).prefix.refcount).write(1);
    core::ptr::addr_of_mut!((*cell).prefix.allocation).write(allocation);
    core::ptr::addr_of_mut!((*cell).prefix.mutex).write(mutex);
    core::ptr::addr_of_mut!((*cell).continuation).write(0);
    (*handle).cell = core::ptr::addr_of_mut!((*cell).prefix);
    if cell.is_null() {
        crate::heap::veneers::heap_panic();
    }
    (*handle).cache = (*cell).prefix.allocation as usize as u32;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FREE_TAG: usize = 0;
    static mut FREE_PTR: *mut u8 = core::ptr::null_mut();
    static mut UNLOCK_PTR: *mut u8 = core::ptr::null_mut();
    static mut DELETE_PTR: *mut RefcountedAllocationCell = core::ptr::null_mut();

    unsafe extern "C" fn record_free(ptr: *mut u8, tag: usize) { FREE_PTR = ptr; FREE_TAG = tag; }
    unsafe extern "C" fn record_unlock(ptr: *mut u8) { UNLOCK_PTR = ptr; }
    unsafe extern "C" fn record_delete(ptr: *mut RefcountedAllocationCell) { DELETE_PTR = ptr; }
    static mut LOCK_PTR: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn record_lock(ptr: *mut u8) -> u32 { LOCK_PTR = ptr; 0x1a }
    unsafe extern "C" fn allocate_cell(size: usize) -> *mut RefcountedAllocationOwnedCell {
        assert_eq!(size, core::mem::size_of::<RefcountedAllocationOwnedCell>());
        std::boxed::Box::into_raw(std::boxed::Box::new(RefcountedAllocationOwnedCell {
            prefix: RefcountedAllocationCell { refcount: -99, allocation: core::ptr::null_mut(), mutex: core::ptr::null_mut() },
            continuation: u32::MAX,
        }))
    }

    #[test]
    fn assignment_replaces_empty_shared_and_final_cells_even_if_lock_fails() {
        let _guard = install();
        unsafe {
            addr_of_mut!(REFCOUNTED_ALLOCATION_HANDLE_ASSIGN_OPS).write(
                RefcountedAllocationHandleAssignOps { lock: record_lock, allocate: allocate_cell });
            for count in [0, 1, 2, i32::MIN] {
                LOCK_PTR = core::ptr::null_mut();
                FREE_PTR = core::ptr::null_mut();
                DELETE_PTR = core::ptr::null_mut();
                UNLOCK_PTR = core::ptr::null_mut();
                let old_allocation = 0x1234usize as *mut u8;
                let old_mutex = 0x5678usize as *mut u8;
                let mut old = RefcountedAllocationCell { refcount: count, allocation: old_allocation, mutex: old_mutex };
                let mut handle = RefcountedAllocationHandle {
                    reserved: 0xdeadbeef,
                    cell: if count == 0 { core::ptr::null_mut() } else { &mut old },
                    cache: u32::MAX,
                };
                let allocation = if count == 2 { core::ptr::null_mut() } else { 0xabcdef00usize as *mut u8 };
                let mutex = if count == 1 { core::ptr::null_mut() } else { 0x9876usize as *mut u8 };
                refcounted_allocation_handle_assign(&mut handle, allocation, mutex);
                assert_eq!(handle.reserved, 0xdeadbeef);
                assert_eq!(handle.cache, allocation as usize as u32);
                let owned = std::boxed::Box::from_raw(handle.cell.cast::<RefcountedAllocationOwnedCell>());
                assert_eq!(owned.prefix.refcount, 1);
                assert_eq!(owned.prefix.allocation, allocation);
                assert_eq!(owned.prefix.mutex, mutex);
                assert_eq!(owned.continuation, 0);
                if count == 0 {
                    assert!(addr_of!(LOCK_PTR).read().is_null());
                    assert!(addr_of!(UNLOCK_PTR).read().is_null());
                } else {
                    assert_eq!(old.refcount, count.wrapping_sub(1));
                    assert_eq!(addr_of!(LOCK_PTR).read(), old_mutex);
                    assert_eq!(addr_of!(UNLOCK_PTR).read(), old_mutex);
                }
                if count == 1 {
                    assert!(old.allocation.is_null());
                    assert_eq!(addr_of!(FREE_PTR).read(), old_allocation);
                    assert_eq!(addr_of!(DELETE_PTR).read(), addr_of_mut!(old));
                } else {
                    assert_eq!(old.allocation, old_allocation);
                    assert!(addr_of!(FREE_PTR).read().is_null());
                    assert!(addr_of!(DELETE_PTR).read().is_null());
                }
            }
        }
    }

    fn install() -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            FREE_TAG = 0; FREE_PTR = core::ptr::null_mut(); UNLOCK_PTR = core::ptr::null_mut(); DELETE_PTR = core::ptr::null_mut();
            addr_of_mut!(REFCOUNTED_ALLOCATION_HANDLE_RELEASE_OPS).write(RefcountedAllocationHandleReleaseOps { free: record_free, unlock: record_unlock, delete: record_delete });
        }
        guard
    }

    #[test]
    fn final_release_frees_unlocks_deletes_and_clears_handle() {
        let _guard = install();
        let allocation = 0x1234usize as *mut u8;
        let mutex = 0x5678usize as *mut u8;
        let mut cell = RefcountedAllocationCell { refcount: 1, allocation, mutex };
        let mut handle = RefcountedAllocationHandle { reserved: 0, cell: &mut cell, cache: 9 };
        unsafe { refcounted_allocation_handle_release(&mut handle) };
        unsafe {
            assert_eq!(addr_of!(FREE_PTR).read(), allocation); assert_eq!(addr_of!(FREE_TAG).read(), ALLOCATION_RELEASE_TAG);
            assert_eq!(addr_of!(UNLOCK_PTR).read(), mutex); assert_eq!(addr_of!(DELETE_PTR).read(), addr_of_mut!(cell));
        }
        assert!(handle.cell.is_null()); assert_eq!(handle.cache, 0); assert!(cell.allocation.is_null());
    }

    #[test]
    fn nonfinal_release_only_unlocks_then_clears_handle() {
        let _guard = install();
        let mutex = 0x5678usize as *mut u8;
        let mut cell = RefcountedAllocationCell { refcount: 2, allocation: 0x1234usize as *mut u8, mutex };
        let mut handle = RefcountedAllocationHandle { reserved: 0, cell: &mut cell, cache: 9 };
        unsafe { refcounted_allocation_handle_release(&mut handle) };
        assert_eq!(cell.refcount, 1); assert_eq!(cell.allocation, 0x1234usize as *mut u8); assert!(handle.cell.is_null()); assert_eq!(handle.cache, 0);
        unsafe { assert_eq!(addr_of!(UNLOCK_PTR).read(), mutex); assert!(addr_of!(FREE_PTR).read().is_null()); assert!(addr_of!(DELETE_PTR).read().is_null()); }
    }

    #[test]
    fn null_cell_leaves_handle_and_operations_untouched() {
        let _guard = install();
        let mut handle = RefcountedAllocationHandle { reserved: 0, cell: core::ptr::null_mut(), cache: 9 };
        unsafe { refcounted_allocation_handle_release(&mut handle) };
        assert!(handle.cell.is_null()); assert_eq!(handle.cache, 9);
        unsafe { assert!(addr_of!(FREE_PTR).read().is_null()); assert!(addr_of!(UNLOCK_PTR).read().is_null()); assert!(addr_of!(DELETE_PTR).read().is_null()); }
    }
}
