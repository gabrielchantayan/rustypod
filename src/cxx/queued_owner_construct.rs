//! `queued_owner_construct` — `FUN_0820278c` @ 0x0820278c.
//! True extent: 132 bytes (128 code bytes, vtable literal at 0x0820280c);
//! the next real function starts at 0x08202810. Full-image A32 decoding
//! verifies two inbound plain BLs (0x081dec54, 0x081ee1e0), seven outgoing
//! plain BLs, and zero predicated BLs in either direction.
//! Construct the task base with scheduler 0xc000, active 1 and timeout 10;
//! store the owner and derived vtable, lock the owner's outer mutex, reload
//! the owner, and mark the old back task when the queue is nonempty. Append
//! the constructed task, unlock the original owner, and return the base result.
//! Deliberate deviations: reuse repr(C) queue layouts (native host pointer
//! widths), existing base/predicate/mutex ports, and fixed-address calls for
//! three unported helpers with host-only seams. No target behavior deviation.

use crate::cxx::counted_container_is_empty::{CountedContainer, counted_container_is_empty};
use crate::cxx::queued_owner_destroy::{QueuedOwner, QueuedOwnerObject};
use crate::cxx::string_object::StringObject;
use crate::cxx::task_base_construct::task_base_construct;
use crate::kernel::sync_mutex::{mutex_lock_counted, mutex_unlock_counted};

#[derive(Clone, Copy)]
pub struct QueuedOwnerConstructOps {
    pub base: unsafe extern "C" fn(*mut u8, u32, *const StringObject, u32, u8, u32) -> *mut u8,
    pub back: unsafe extern "C" fn(*mut CountedContainer) -> *mut u8,
    pub mark: unsafe extern "C" fn(*mut u8),
    pub push: unsafe extern "C" fn(*mut CountedContainer, *mut QueuedOwnerObject),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_back(queue: *mut CountedContainer) -> *mut u8 {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut CountedContainer) -> *mut u8>(0x081d_a690)(queue)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_mark(task: *mut u8) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8)>(0x0829_0690)(task)
}
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_push(queue: *mut CountedContainer, task: *mut QueuedOwnerObject) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut CountedContainer, *mut QueuedOwnerObject)>(0x081d_a7a8)(queue, task)
}
#[cfg(target_os = "none")]
const OPS: QueuedOwnerConstructOps = QueuedOwnerConstructOps {
    base: task_base_construct, back: retail_back, mark: retail_mark, push: retail_push,
};
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_back(_: *mut CountedContainer) -> *mut u8 { panic!("requires retail back 0x081da690") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_mark(_: *mut u8) { panic!("requires retail task mark 0x08290690") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_push(_: *mut CountedContainer, _: *mut QueuedOwnerObject) { panic!("requires retail push 0x081da7a8") }
#[cfg(not(target_os = "none"))]
pub static mut QUEUED_OWNER_CONSTRUCT_OPS: QueuedOwnerConstructOps = QueuedOwnerConstructOps {
    base: task_base_construct, back: missing_back, mark: missing_mark, push: missing_push,
};

/// # Safety
/// Storage, name, owner, queue and its old back must satisfy the retail base,
/// locking, back, mark and append contracts. No NULL or allocation guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn queued_owner_construct(
    storage: *mut QueuedOwnerObject,
    priority: u32,
    owner: *mut QueuedOwner,
    name: *const StringObject,
) -> *mut QueuedOwnerObject {
    #[cfg(target_os = "none")]
    let ops = OPS;
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(QUEUED_OWNER_CONSTRUCT_OPS));
    let object = (ops.base)(storage.cast(), priority, name, 0xc000, 1, 10).cast::<QueuedOwnerObject>();
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*object).owner), owner);
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*object).words[0]), 0x08991094);
    let lock = core::ptr::addr_of_mut!((*owner).lock);
    mutex_lock_counted(lock);
    let owner = core::ptr::read_volatile(core::ptr::addr_of!((*object).owner));
    let queue = core::ptr::addr_of_mut!((*owner).container);
    if counted_container_is_empty(queue) == 0 {
        let previous = (ops.back)(queue);
        (ops.mark)(previous);
    }
    (ops.push)(queue, object);
    mutex_unlock_counted(lock);
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::sync_mutex::{Mutex, CountedMutex};
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut PREVIOUS: [u32; 10] = [0; 10];
    static mut APPENDED: *mut QueuedOwnerObject = core::ptr::null_mut();

    unsafe extern "C" fn base(p: *mut u8, _: u32, _: *const StringObject, _: u32, _: u8, _: u32) -> *mut u8 {
        // Enough storage for the base's entire 0x28-byte prefix; preserve sentinel tail.
        core::ptr::write_bytes(p, 0, 0x28);
        p
    }
    unsafe extern "C" fn back(q: *mut CountedContainer) -> *mut u8 {
        assert_ne!((*q).container_words[8], 0);
        core::ptr::addr_of_mut!(PREVIOUS).cast()
    }
    unsafe extern "C" fn mark(p: *mut u8) {
        // Reference for the verified 0x08290690 helper: no write for inactive tasks.
        if p.add(4).cast::<u32>().read() != 0 { p.add(0x21).write(1); }
    }
    unsafe extern "C" fn push(q: *mut CountedContainer, p: *mut QueuedOwnerObject) {
        assert_eq!((*(*p).owner).lock.hold_count, 1);
        assert_eq!((*p).words[0], 0x08991094);
        APPENDED = p;
        (*q).container_words[8] += 1;
    }
    fn lock() -> CountedMutex {
        CountedMutex { mutex: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 }, hold_count: 0 }
    }

    #[test]
    fn empty_and_nonempty_queues_mark_only_the_previous_active_task() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = QUEUED_OWNER_CONSTRUCT_OPS;
            QUEUED_OWNER_CONSTRUCT_OPS = QueuedOwnerConstructOps { base, back, mark, push };
            for (count, active, flag) in [(0, 1, 7), (1, 0, 7), (1, 1, 7), (3, 1, 0)] {
                PREVIOUS = [0; 10];
                PREVIOUS[1] = active;
                core::ptr::addr_of_mut!(PREVIOUS).cast::<u8>().add(0x21).write(flag);
                APPENDED = core::ptr::null_mut();
                let mut owner = QueuedOwner { header: 0, container: CountedContainer {
                    container_words: [0; 11], lock: lock(),
                }, reserved: 0, lock: lock() };
                owner.container.container_words[8] = count;
                let mut object = QueuedOwnerObject { words: [0xa5a5a5a5; 10], owner: core::ptr::null_mut() };
                let result = queued_owner_construct(&mut object, 0x18, &mut owner, core::ptr::null());
                assert_eq!(result, core::ptr::addr_of_mut!(object));
                assert_eq!(APPENDED, result);
                assert_eq!(owner.container.container_words[8], count + 1);
                assert_eq!(core::ptr::addr_of!(PREVIOUS).cast::<u8>().add(0x21).read(),
                    if count != 0 && active != 0 { 1 } else { flag });
                assert_eq!(object.words[8], 0, "new task was not marked");
                assert_eq!(owner.lock.hold_count, 0);
                assert_eq!(owner.container.lock.hold_count, 0);
            }
            QUEUED_OWNER_CONSTRUCT_OPS = saved;
        }
    }
}
