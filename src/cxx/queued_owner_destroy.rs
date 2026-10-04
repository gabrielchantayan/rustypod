//! `queued_owner_destroy` — `FUN_08202828` @ 0x08202828.
//! True extent: 100 bytes to 0x0820288c (96 code bytes, literal 0x08991094).
//! Raw A32 decoding finds two inbound plain BLs (0x081ee21c, 0x0820281c),
//! six outgoing plain BLs and no predicated BLs in either direction.
//! Install the derived vtable, lock owner+0x40, reload the owner pointer,
//! pop the back of its container at +4, and query emptiness. If nonempty,
//! fetch the new back and notify that returned object via 0x082905f8.
//! Unlock the originally selected owner, then tail-delegate base destruction.
//! Deliberate deviations: repr(C) widens native pointer-containing layouts on
//! hosts; the four unported helpers retain fixed-address firmware dispatch
//! with host-only replacement seams. The final tail branch is a Rust return.
//! Existing counted mutex and container predicate ports are called directly.

use crate::cxx::counted_container_is_empty::{CountedContainer, counted_container_is_empty};
use crate::kernel::sync_mutex::{CountedMutex, mutex_lock_counted, mutex_unlock_counted};

#[repr(C)]
pub struct QueuedOwner {
    pub header: u32,
    pub container: CountedContainer,
    pub reserved: u32,
    pub lock: CountedMutex,
}

#[repr(C)]
pub struct QueuedOwnerObject {
    pub words: [u32; 10],
    pub owner: *mut QueuedOwner,
}

#[derive(Clone, Copy)]
pub struct QueuedOwnerDestroyOps {
    pub pop_back: unsafe extern "C" fn(*mut CountedContainer),
    pub back: unsafe extern "C" fn(*mut CountedContainer) -> *mut u8,
    pub notify: unsafe extern "C" fn(*mut u8),
    pub base_destroy: unsafe extern "C" fn(*mut QueuedOwnerObject) -> *mut QueuedOwnerObject,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_pop_back(queue: *mut CountedContainer) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut CountedContainer)>(0x081d_a620)(queue)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_back(queue: *mut CountedContainer) -> *mut u8 {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut CountedContainer) -> *mut u8>(0x081d_a690)(queue)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify(object: *mut u8) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8)>(0x0829_05f8)(object)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_base_destroy(object: *mut QueuedOwnerObject) -> *mut QueuedOwnerObject {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut QueuedOwnerObject) -> *mut QueuedOwnerObject>(0x0829_076c)(object)
}

#[cfg(target_os = "none")]
const OPS: QueuedOwnerDestroyOps = QueuedOwnerDestroyOps {
    pop_back: retail_pop_back, back: retail_back, notify: retail_notify, base_destroy: retail_base_destroy,
};
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pop(_: *mut CountedContainer) { panic!("requires retail pop-back 0x081da620") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_back(_: *mut CountedContainer) -> *mut u8 { panic!("requires retail back 0x081da690") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notify(_: *mut u8) { panic!("requires retail notification 0x082905f8") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base(_: *mut QueuedOwnerObject) -> *mut QueuedOwnerObject { panic!("requires retail base destructor 0x0829076c") }
#[cfg(not(target_os = "none"))]
pub static mut QUEUED_OWNER_DESTROY_OPS: QueuedOwnerDestroyOps = QueuedOwnerDestroyOps {
    pop_back: missing_pop, back: missing_back, notify: missing_notify, base_destroy: missing_base,
};

/// # Safety
/// The object, its owner, container storage and remaining queued item must be
/// valid for their retail destruct/pop/back/notification contracts. No NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn queued_owner_destroy(object: *mut QueuedOwnerObject) -> *mut QueuedOwnerObject {
    #[cfg(target_os = "none")]
    let ops = OPS;
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(QUEUED_OWNER_DESTROY_OPS));
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*object).words[0]), 0x08991094);
    let owner = core::ptr::read_volatile(core::ptr::addr_of!((*object).owner));
    let lock = core::ptr::addr_of_mut!((*owner).lock);
    mutex_lock_counted(lock);
    let owner = core::ptr::read_volatile(core::ptr::addr_of!((*object).owner));
    let queue = core::ptr::addr_of_mut!((*owner).container);
    (ops.pop_back)(queue);
    if counted_container_is_empty(queue) == 0 {
        let next = (ops.back)(queue);
        (ops.notify)(next);
    }
    mutex_unlock_counted(lock);
    (ops.base_destroy)(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::Mutex;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut NOTIFIED: u32 = 0;
    static mut ITEM: u32 = 0;

    fn mutex(count: u32) -> CountedMutex {
        CountedMutex { mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 }, hold_count: count }
    }
    unsafe extern "C" fn pop(queue: *mut CountedContainer) {
        let owner = (queue as *mut u8).sub(core::mem::offset_of!(QueuedOwner, container)).cast::<QueuedOwner>();
        assert_eq!((*owner).lock.hold_count, 8);
        let count = &mut (*queue).container_words[8];
        if *count != 0 { *count -= 1; }
    }
    unsafe extern "C" fn back(queue: *mut CountedContainer) -> *mut u8 {
        assert_ne!((*queue).container_words[8], 0);
        core::ptr::addr_of_mut!(ITEM).cast()
    }
    unsafe extern "C" fn notify(item: *mut u8) {
        assert_eq!(item, core::ptr::addr_of_mut!(ITEM).cast());
        NOTIFIED += 1;
        item.cast::<u32>().write(0x12345678);
    }
    unsafe extern "C" fn base(object: *mut QueuedOwnerObject) -> *mut QueuedOwnerObject {
        assert_eq!((*object).words[0], 0x08991094);
        assert_eq!((*(*object).owner).lock.hold_count, 7);
        (*object).words[0] = 0x089a7160;
        object
    }

    #[test]
    fn removal_notifies_only_when_a_successor_remains_and_balances_locks() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = QUEUED_OWNER_DESTROY_OPS;
            QUEUED_OWNER_DESTROY_OPS = QueuedOwnerDestroyOps { pop_back: pop, back, notify, base_destroy: base };
            for count in [0, 1, 2, 17, u32::MAX] {
                NOTIFIED = 0;
                ITEM = 0;
                let mut owner = QueuedOwner {
                    header: 0, container: CountedContainer { container_words: [0; 11], lock: mutex(3) },
                    reserved: 0, lock: mutex(7),
                };
                owner.container.container_words[8] = count;
                let mut object = QueuedOwnerObject { words: [0xa5a5a5a5; 10], owner: &mut owner };
                assert_eq!(queued_owner_destroy(&mut object), &mut object as *mut _);
                let remaining = count.saturating_sub(1);
                assert_eq!(owner.container.container_words[8], remaining);
                assert_eq!(NOTIFIED, u32::from(remaining != 0));
                assert_eq!(ITEM, if remaining != 0 { 0x12345678 } else { 0 });
                assert_eq!(owner.lock.hold_count, 7);
                assert_eq!(owner.container.lock.hold_count, 3);
                assert_eq!(object.words[0], 0x089a7160);
                assert_eq!(&object.words[1..], &[0xa5a5a5a5; 9]);
            }
            QUEUED_OWNER_DESTROY_OPS = saved;
        }
    }

}
