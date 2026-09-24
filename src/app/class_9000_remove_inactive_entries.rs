//! `class_9000_remove_inactive_entries` — original: `FUN_08109bd0` @
//! **0x08109bd0** (108 bytes, `0x08109bd0..0x08109c3c`; the next function
//! starts at `0x08109c3c`). Raw ARM decoding verifies one unconditional `bl`
//! (`array_element_at`) and two predicated/unconditional virtual `blx` calls.
//!
//! Algorithm: destroy the optional object at `+0x6c`, clear that field, then
//! scan the strided entry array at `+0x4c`. An entry whose pointed-to object's
//! byte `+0x2c` is zero is removed through this object's vtable slot `+0xac`;
//! otherwise the index advances. The removal callback owns count and storage
//! mutation, so the same index is retried after every removal. Deliberate
//! deviation: the two virtual callees have no recovered identities and host
//! builds inject them; target builds dispatch their verified vtable words.

#[cfg(target_os = "none")]
use crate::cxx::array_element_at::{array_element_at, StridedArray};

const ENTRIES_OFFSET: usize = 0x4c;
const ENTRY_COUNT_OFFSET: usize = 0x50;
const RETAINED_OBJECT_OFFSET: usize = 0x6c;
const ENTRY_ACTIVE_OFFSET: usize = 0x2c;
const DESTROY_VTABLE_WORD: usize = 1;
const REMOVE_VTABLE_WORD: usize = 0xac / 4;

type DestroyRetained = unsafe extern "C" fn(*mut u8);
type RemoveInactiveEntry = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct Class9000RemoveInactiveEntriesOps {
    pub destroy_retained: DestroyRetained,
    pub entry_at: unsafe extern "C" fn(*mut u8, i32) -> *mut *mut u8,
    pub remove_inactive_entry: RemoveInactiveEntry,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_destroy(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_entry_at(_: *mut u8, _: i32) -> *mut *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn no_remove(_: *mut u8) {}
#[cfg(not(target_os = "none"))]
pub const DEFAULT_CLASS_9000_REMOVE_INACTIVE_ENTRIES_OPS: Class9000RemoveInactiveEntriesOps = Class9000RemoveInactiveEntriesOps {
    destroy_retained: no_destroy,
    entry_at: no_entry_at,
    remove_inactive_entry: no_remove,
};
#[cfg(not(target_os = "none"))]
pub static mut CLASS_9000_REMOVE_INACTIVE_ENTRIES_OPS: Class9000RemoveInactiveEntriesOps = DEFAULT_CLASS_9000_REMOVE_INACTIVE_ENTRIES_OPS;

/// Removes every inactive entry while retaining the retail callback order.
///
/// # Safety
/// `this` must be a valid class-0x9000 object through `+0x6c`; its embedded
/// strided array and all reached entry pointers must be readable. Target
/// vtable slots `+0x04` and `+0xac` must be callable.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.class_9000_remove_inactive_entries")]
#[inline(never)]
pub unsafe extern "C" fn class_9000_remove_inactive_entries(this: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let retained = unsafe { this.add(RETAINED_OBJECT_OFFSET).cast::<u32>().read_volatile() as *mut u8 };
        if !retained.is_null() {
            let vtable = unsafe { retained.cast::<u32>().read_volatile() as *const u32 };
            let destroy: DestroyRetained = unsafe { core::mem::transmute(vtable.add(DESTROY_VTABLE_WORD).read_volatile() as usize) };
            unsafe { destroy(retained); }
        }
        unsafe { this.add(RETAINED_OBJECT_OFFSET).cast::<u32>().write_volatile(0); }
        let entries = unsafe { this.add(ENTRIES_OFFSET).cast::<StridedArray>() };
        let mut index = 0;
        while index < unsafe { this.add(ENTRY_COUNT_OFFSET).cast::<i32>().read_volatile() } {
            let entry = unsafe { array_element_at(entries, index) as usize as *const u32 };
            let item = unsafe { entry.read_volatile() as *mut u8 };
            if unsafe { item.add(ENTRY_ACTIVE_OFFSET).read_volatile() } == 0 {
                let vtable = unsafe { this.cast::<u32>().read_volatile() as *const u32 };
                let remove: RemoveInactiveEntry = unsafe { core::mem::transmute(vtable.add(REMOVE_VTABLE_WORD).read_volatile() as usize) };
                unsafe { remove(this); }
            } else {
                index += 1;
            }
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = unsafe { CLASS_9000_REMOVE_INACTIVE_ENTRIES_OPS };
        let retained = unsafe { this.add(RETAINED_OBJECT_OFFSET).cast::<*mut u8>().read_unaligned() };
        if !retained.is_null() { unsafe { (ops.destroy_retained)(retained); } }
        unsafe { this.add(RETAINED_OBJECT_OFFSET).cast::<*mut u8>().write_unaligned(core::ptr::null_mut()); }
        let mut index = 0;
        while index < unsafe { this.add(ENTRY_COUNT_OFFSET).cast::<i32>().read_unaligned() } {
            let entry = unsafe { (ops.entry_at)(this, index) };
            let item = unsafe { entry.read() };
            if unsafe { item.add(ENTRY_ACTIVE_OFFSET).read() } == 0 {
                unsafe { (ops.remove_inactive_entry)(this); }
            } else {
                index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ENTRIES: [*mut u8; 3] = [core::ptr::null_mut(); 3];
    static mut EVENTS: [u8; 4] = [0; 4];
    static mut EVENT_COUNT: usize = 0;

    unsafe extern "C" fn destroy(_: *mut u8) { unsafe { EVENTS[EVENT_COUNT] = 1; EVENT_COUNT += 1; } }
    unsafe extern "C" fn entry_at(_: *mut u8, index: i32) -> *mut *mut u8 { unsafe { ENTRIES.as_mut_ptr().add(index as usize) } }
    unsafe extern "C" fn remove(this: *mut u8) {
        unsafe {
            EVENTS[EVENT_COUNT] = 2; EVENT_COUNT += 1;
            ENTRIES[0] = ENTRIES[1]; ENTRIES[1] = ENTRIES[2];
            let count = this.add(ENTRY_COUNT_OFFSET).cast::<i32>().read_unaligned();
            this.add(ENTRY_COUNT_OFFSET).cast::<i32>().write_unaligned(count - 1);
        }
    }

    #[test]
    fn destroys_retained_object_and_retries_removed_index() {
        let _lock = LOCK.lock();
        let mut object = [0u8; 0x70];
        let mut retained = [0u8; 8];
        let mut inactive = [0u8; 0x30];
        let mut active = [0u8; 0x30]; active[ENTRY_ACTIVE_OFFSET] = 1;
        unsafe {
            ENTRIES = [inactive.as_mut_ptr(), active.as_mut_ptr(), core::ptr::null_mut()]; EVENTS = [0; 4]; EVENT_COUNT = 0;
            object.as_mut_ptr().add(RETAINED_OBJECT_OFFSET).cast::<*mut u8>().write_unaligned(retained.as_mut_ptr());
            object.as_mut_ptr().add(ENTRY_COUNT_OFFSET).cast::<i32>().write_unaligned(2);
            CLASS_9000_REMOVE_INACTIVE_ENTRIES_OPS = Class9000RemoveInactiveEntriesOps { destroy_retained: destroy, entry_at, remove_inactive_entry: remove };
            class_9000_remove_inactive_entries(object.as_mut_ptr());
            assert_eq!(EVENTS[..EVENT_COUNT], [1, 2]);
            assert_eq!(object.as_ptr().add(ENTRY_COUNT_OFFSET).cast::<i32>().read_unaligned(), 1);
            assert!(object.as_ptr().add(RETAINED_OBJECT_OFFSET).cast::<*mut u8>().read_unaligned().is_null());
        }
    }
}
