//! Drain a deque and conditionally release its polymorphic objects.
//!
//! `FUN_08215664` @ 0x08215664: true size 84 bytes, ending before the
//! independent push at 0x082156b8. Raw A32 contains two plain BLs, zero
//! predicated BLs, one BLX and one BLXNE. Whole-image decoding finds two
//! plain inbound BLs (0x0818bc5c, 0x08215974), no predicated inbound BLs.
//! Check emptiness, remove the front object, query virtual slot +0x18,
//! and invoke the current vtable's +0x04 slot only when status bit 0 is set.
//! Repeat until empty. The status call precedes the release-only NULL guard.
//!
//! Deliberate deviations: retain stock deque_front_remove at 0x082156f0
//! because its existing Rust port returns the cursor instead of the object
//! pointer loaded through it. Hosts model removal for a contiguous native
//! pointer fixture, not segmented deque allocation. Native-width vtable
//! entries preserve word indices; concrete virtual method identities remain
//! unknown. The count check uses BlockDeque.count, avoiding the target-only
//! +0x20 offset in container_is_empty on widened host layouts.

use crate::heap::block_deque::BlockDeque;

pub type DrainStatus = unsafe extern "C" fn(*mut DrainObject) -> u32;
pub type DrainRelease = unsafe extern "C" fn(*mut DrainObject);

#[repr(C)]
pub struct DrainVtable {
    pub slot_0: usize,
    pub release: DrainRelease,
    pub slots_2_to_5: [usize; 4],
    pub status: DrainStatus,
}

#[repr(C)]
pub struct DrainObject {
    pub vtable: *const DrainVtable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(DrainVtable, status)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 4] = [0; core::mem::offset_of!(DrainVtable, release)];

#[inline(always)]
unsafe fn remove_front(deque: *mut BlockDeque) -> *mut DrainObject {
    #[cfg(target_os = "none")]
    {
        let remove: unsafe extern "C" fn(*mut BlockDeque) -> *mut DrainObject =
            core::mem::transmute(0x0821_56f0usize);
        remove(deque)
    }
    #[cfg(not(target_os = "none"))]
    {
        let cursor = (*deque).begin.cur.cast::<*mut DrainObject>();
        let object = cursor.read();
        (*deque).begin.cur = cursor.add(1).cast();
        (*deque).count -= 1;
        object
    }
}

/// Drain and conditionally release all front objects.
///
/// # Safety
/// `deque` must be valid for stock front removal. Every removed object must
/// be non-NULL with a callable status slot; a set low status bit requires a
/// callable release slot in its vtable after the status callback. On hosts,
/// the begin cursor must reference `count` contiguous native object pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn deque_drain_release(deque: *mut BlockDeque) {
    while (*deque).count != 0 {
        let object = remove_front(deque);
        let status = (*(*object).vtable).status;
        if status(object) & 1 != 0 && !object.is_null() {
            let release = (*(*object).vtable).release;
            release(object);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::block_deque::DequeIter;

    #[repr(C)]
    struct Receiver {
        base: DrainObject,
        flags: u32,
        queries: u32,
        releases: u32,
        deque: *mut BlockDeque,
        expected_remaining: u32,
    }

    unsafe extern "C" fn status(object: *mut DrainObject) -> u32 {
        let receiver = &mut *object.cast::<Receiver>();
        assert_eq!((*receiver.deque).count, receiver.expected_remaining);
        receiver.queries += 1;
        receiver.base.vtable = &AFTER_STATUS;
        receiver.flags
    }
    unsafe extern "C" fn wrong_release(_: *mut DrainObject) {
        panic!("release must reload the vtable after status")
    }
    unsafe extern "C" fn release(object: *mut DrainObject) {
        (*object.cast::<Receiver>()).releases += 1;
    }
    static BEFORE_STATUS: DrainVtable = DrainVtable {
        slot_0: 0, release: wrong_release, slots_2_to_5: [0; 4], status,
    };
    static AFTER_STATUS: DrainVtable = DrainVtable {
        slot_0: 0, release, slots_2_to_5: [0; 4], status,
    };

    fn empty() -> BlockDeque {
        BlockDeque {
            begin: DequeIter::NULL, end: DequeIter::NULL, count: 0,
            map: core::ptr::null_mut(), map_cap: 0,
        }
    }

    #[test]
    fn empty_never_reads_null_cursor() {
        let mut deque = empty();
        unsafe { deque_drain_release(&mut deque) };
        assert_eq!(deque.count, 0);
        assert!(deque.begin.cur.is_null());
    }

    #[test]
    fn removes_before_query_and_releases_only_low_bit_using_updated_vtable() {
        let mut deque = empty();
        let flags = [0, 2, 0x8000_0000, 1, 3, u32::MAX];
        let mut receivers = flags.map(|flags| Receiver {
            base: DrainObject { vtable: &BEFORE_STATUS }, flags,
            queries: 0, releases: 0, deque: &mut deque, expected_remaining: 0,
        });
        for (index, receiver) in receivers.iter_mut().enumerate() {
            receiver.expected_remaining = (flags.len() - index - 1) as u32;
        }
        let mut slots = receivers.each_mut().map(|r| &mut r.base as *mut DrainObject);
        deque.begin.cur = slots.as_mut_ptr().cast();
        deque.count = slots.len() as u32;
        unsafe { deque_drain_release(&mut deque) };
        assert_eq!(deque.count, 0);
        for receiver in &receivers {
            assert_eq!(receiver.queries, 1);
            assert_eq!(receiver.releases, receiver.flags & 1);
        }
        unsafe { deque_drain_release(&mut deque) };
        for receiver in &receivers { assert_eq!(receiver.queries, 1); }
    }
}
