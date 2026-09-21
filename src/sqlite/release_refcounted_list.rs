//! Release a target-width list of ref-counted objects.
//!
//! `release_refcounted_list` — retailOS `FUN_082bead4` at load address
//! `0x082bead4` (120 bytes; true extent `0x082bead4..0x082beb4c`, followed by
//! a separately linked function at `0x082beb4c`). Raw `osos.dec` decoding
//! verifies two plain `bl` calls (`FUN_0838d878` and `tracked_free` @
//! `0x083906f4`) and one predicated `blxne` virtual destructor call. The
//! function has three inbound plain-BL call sites.
//!
//! It visits each non-NULL object in the list at `owner + 0x10c` while its
//! signed count at `owner + 0x110` permits, calls the requested virtual slot,
//! then decrements the object's reference count and invokes its destroy slot
//! only for the final reference. Finally it frees the list and clears both
//! owner words. Deliberate deviation: the unported `FUN_0838d878` is expressed
//! here by its raw-verified decrement-and-destroy sequence; host builds use
//! operations because target-width function pointers cannot hold host code.

use crate::heap::tracked::tracked_free;

const OBJECT_LIST: usize = 0x10c;
const OBJECT_COUNT: usize = 0x110;
const OBJECT_REFERENCE_COUNT: usize = 4;
const OBJECT_DESTROY_SLOT: usize = 0x10;

type ObjectCallback = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RefcountedListReleaseOps {
    pub callback: unsafe extern "C" fn(*mut u8, u32),
    pub release: unsafe extern "C" fn(*mut u8),
    pub free: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_callback(_object: *mut u8, _slot: u32) { panic!("install refcounted-list release operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_object: *mut u8) { panic!("install refcounted-list release operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_free(_objects: *mut u8) { panic!("install refcounted-list release operations") }

#[cfg(not(target_os = "none"))]
pub static mut REFCOUNTED_LIST_RELEASE_OPS: RefcountedListReleaseOps = RefcountedListReleaseOps {
    callback: missing_callback,
    release: missing_release,
    free: missing_free,
};

unsafe fn release_final_reference(object: *mut u8) {
    let references = object.add(OBJECT_REFERENCE_COUNT).cast::<u32>();
    let prior = references.read();
    references.write(prior.wrapping_sub(1));
    if prior != 1 { return; }

    let vtable = object.cast::<u32>().read() as usize as *const u32;
    let destroy: ObjectCallback = core::mem::transmute(vtable.add(OBJECT_DESTROY_SLOT / 4).read() as usize);
    destroy(object);
}

/// Releases every non-NULL object preceding the first NULL list entry.
///
/// # Safety
///
/// `owner` must have target-width list and signed-count words at `+0x10c` and
/// `+0x110`. Each visited object must support `callback_slot` and have the
/// ref-count/destroy layout verified in the raw callee.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn release_refcounted_list(owner: *mut u8, callback_slot: u32) {
    let list_word = owner.add(OBJECT_LIST).cast::<u32>();
    let objects = list_word.read() as usize as *mut u32;
    if objects.is_null() { return; }

    let count = owner.add(OBJECT_COUNT).cast::<i32>().read();
    let mut index = 0_i32;
    while index < count {
        let object = objects.add(index as usize).read() as usize as *mut u8;
        if object.is_null() { break; }

        #[cfg(target_os = "none")]
        {
            let vtable = object.cast::<u32>().read() as usize as *const u32;
            let callback_address = vtable.add(callback_slot as usize / 4).read();
            if callback_address != 0 {
                let callback: ObjectCallback = core::mem::transmute(callback_address as usize);
                callback(object);
            }
            release_final_reference(object);
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_LIST_RELEASE_OPS));
            (ops.callback)(object, callback_slot);
            (ops.release)(object);
        }
        index += 1;
    }

    #[cfg(target_os = "none")]
    tracked_free(objects.cast());
    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(REFCOUNTED_LIST_RELEASE_OPS));
        (ops.free)(objects.cast());
    }
    owner.add(OBJECT_COUNT).cast::<u32>().write_volatile(0);
    list_word.write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};

    const FIXTURE_LEN: usize = 0x1000;
    const OWNER: usize = 0x100;
    const OBJECTS: usize = 0x300;
    const FIRST: usize = 0x400;
    const SECOND: usize = 0x500;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CALLBACKS: AtomicUsize = AtomicUsize::new(0);
    static RELEASES: AtomicUsize = AtomicUsize::new(0);
    static FREED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn callback(_object: *mut u8, slot: u32) {
        assert_eq!(slot, 0x44);
        CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
    unsafe extern "C" fn release(_object: *mut u8) { RELEASES.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn free(objects: *mut u8) { FREED.store(objects as usize, Ordering::Relaxed); }

    #[test]
    fn releases_until_null_then_clears_and_frees_the_list() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::SQLITE_RELEASE_REFCOUNTED_LIST, FIXTURE_LEN) else { return; };
        unsafe {
            REFCOUNTED_LIST_RELEASE_OPS = RefcountedListReleaseOps { callback, release, free };
            CALLBACKS.store(0, Ordering::Relaxed);
            RELEASES.store(0, Ordering::Relaxed);
            FREED.store(0, Ordering::Relaxed);
            let owner = base.add(OWNER);
            let objects = base.add(OBJECTS).cast::<u32>();
            owner.add(OBJECT_LIST).cast::<u32>().write(objects as usize as u32);
            owner.add(OBJECT_COUNT).cast::<i32>().write(3);
            objects.write(base.add(FIRST) as usize as u32);
            objects.add(1).write(base.add(SECOND) as usize as u32);
            objects.add(2).write(0);
            release_refcounted_list(owner, 0x44);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 2);
            assert_eq!(RELEASES.load(Ordering::Relaxed), 2);
            assert_eq!(FREED.load(Ordering::Relaxed), objects as usize);
            assert_eq!(owner.add(OBJECT_LIST).cast::<u32>().read(), 0);
            assert_eq!(owner.add(OBJECT_COUNT).cast::<u32>().read(), 0);
        }
    }

    #[test]
    fn null_list_is_inert_and_nonpositive_counts_still_free() {
        let _guard = TEST_LOCK.lock();
        let Some(base) = try_map_u32_slab(hints::SQLITE_RELEASE_REFCOUNTED_LIST_EMPTY, FIXTURE_LEN) else { return; };
        unsafe {
            REFCOUNTED_LIST_RELEASE_OPS = RefcountedListReleaseOps { callback, release, free };
            CALLBACKS.store(0, Ordering::Relaxed);
            RELEASES.store(0, Ordering::Relaxed);
            FREED.store(0, Ordering::Relaxed);
            let owner = base.add(OWNER);
            release_refcounted_list(owner, 0x44);
            assert_eq!(FREED.load(Ordering::Relaxed), 0);
            let objects = base.add(OBJECTS).cast::<u32>();
            owner.add(OBJECT_LIST).cast::<u32>().write(objects as usize as u32);
            owner.add(OBJECT_COUNT).cast::<i32>().write(-1);
            release_refcounted_list(owner, 0x44);
            assert_eq!(CALLBACKS.load(Ordering::Relaxed), 0);
            assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
            assert_eq!(FREED.load(Ordering::Relaxed), objects as usize);
            assert_eq!(owner.add(OBJECT_LIST).cast::<u32>().read(), 0);
            assert_eq!(owner.add(OBJECT_COUNT).cast::<u32>().read(), 0);
        }
    }
}
