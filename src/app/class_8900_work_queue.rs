//! `class_8900_work_queue_enqueue` — original: `FUN_081ee660` @
//! **0x081ee660** (**68 bytes**, 0x081ee660..0x081ee6a4; the next separately
//! linked function opens `push {r4, r5, r6, r7, r8, lr}` at 0x081ee6a4, and
//! there is no literal pool). **9 direct `bl` call sites**, verified by
//! decoding every ARM B/BL word in `work/firmware/osos.dec`: 0x081ee5e0,
//! 0x081ee640, 0x081ee998, 0x081eebdc, 0x081eec78, 0x081eed10, 0x081eedec,
//! 0x081eeef0, and 0x081eef44. All nine are unconditional; there are no
//! predicated calls, direct tail branches, or aligned data words targeting
//! this entry.
//!
//! The class-0x8900 work queue's synchronized intrusive FIFO insertion. It
//! locks the embedded mutex at +0x14, installs `work` as both head and tail
//! when the FIFO was empty or writes it to the old tail's +0x18 link, records
//! the new tail, broadcasts the condition variable at +0x1c, then
//! tail-branches to `mutex_unlock`. The work item's next link is deliberately
//! **not** initialized: the preceding constructors own that initialization,
//! and the stock routine only overwrites an existing tail's link.
//!
//! Deliberate deviation: the ARM tail branch becomes a direct call to the
//! already ported `mutex_unlock`; its scratch return is void in this ABI.
//! `repr(C)` fields express target words rather than literal byte offsets, so
//! the 32-bit layout is exact while host fixtures retain disjoint pointers.


use crate::kernel::condvar::{condvar_broadcast, CondVar};
use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

/// The class-0x8900 receiver portion used by the work queue. The preceding
/// five words include the class state byte callers inspect at +0x08; this
/// routine only uses the synchronization and FIFO fields below.
#[repr(C)]
pub struct Class8900WorkQueue {
    /// +0x00..+0x10: class state outside this routine's responsibility.
    pub state_before_mutex: [u32; 5],
    /// +0x14: RTXC mutex protecting the FIFO and its waiter list.
    pub mutex: Mutex,
    /// +0x1c: waiter list broadcast after every insertion.
    pub work_available: CondVar,
    /// +0x28: oldest queued work item.
    pub head: *mut Class8900QueuedWork,
    /// +0x2c: newest queued work item.
    pub tail: *mut Class8900QueuedWork,
}

/// A 32-byte work record as seen by the FIFO. Its owning constructors fill
/// the first six words; only the `next` link at +0x18 belongs to this helper.
#[repr(C)]
pub struct Class8900QueuedWork {
    /// +0x00..+0x14: command-specific record data.
    pub payload: [u32; 6],
    /// +0x18: successor in the pending-work FIFO.
    pub next: *mut Class8900QueuedWork,
    /// +0x1c: command-specific trailing word.
    pub trailing: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::offset_of!(Class8900WorkQueue, mutex)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(Class8900WorkQueue, work_available)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(Class8900WorkQueue, head)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x2c] = [0; core::mem::offset_of!(Class8900WorkQueue, tail)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(Class8900QueuedWork, next)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::size_of::<Class8900QueuedWork>()];

/// class_8900_work_queue_enqueue — original: `FUN_081ee660` @ 0x081ee660
/// (68 bytes; 9 unconditional direct `bl` callers, binary-verified — see the
/// module header).
///
/// Appends `work` to `this`'s pending-work FIFO while holding its mutex,
/// wakes all waiters, and releases the mutex. Neither pointer is NULL-checked,
/// matching the original.
///
/// # Safety
///
/// `this` must point to a live initialized queue and `work` must point to a
/// live 32-byte record. The queue's stored tail, if non-NULL, must be a live
/// [`Class8900QueuedWork`].
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_work_queue_enqueue(
    this: *mut Class8900WorkQueue,
    work: *mut Class8900QueuedWork,
) {
    mutex_lock(&mut (*this).mutex);

    if (*this).head.is_null() {
        (*this).head = work;
    } else {
        (*(*this).tail).next = work;
    }
    (*this).tail = work;

    condvar_broadcast(&mut (*this).work_available);
    mutex_unlock(&mut (*this).mutex);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::kernel::condvar::ListHead;
    use core::ptr::null_mut;

    fn queue() -> Class8900WorkQueue {
        Class8900WorkQueue {
            state_before_mutex: [0; 5],
            mutex: Mutex { sem_cell: null_mut(), unused: 0 },
            work_available: CondVar {
                lock_obj: null_mut(),
                waiters: ListHead { head: null_mut(), tail: null_mut() },
            },
            head: null_mut(),
            tail: null_mut(),
        }
    }

    fn work(next: *mut Class8900QueuedWork) -> Class8900QueuedWork {
        Class8900QueuedWork { payload: [0; 6], next, trailing: 0 }
    }

    #[test]
    fn first_work_becomes_both_endpoints_without_clobbering_its_link() {
        let mut queue = queue();
        let mut retained_successor = work(null_mut());
        let mut first = work(&mut retained_successor);

        unsafe { class_8900_work_queue_enqueue(&mut queue, &mut first) };

        assert!(core::ptr::eq(queue.head, &mut first));
        assert!(core::ptr::eq(queue.tail, &mut first));
        assert!(core::ptr::eq(first.next, &mut retained_successor));
        assert!(queue.work_available.waiters.head.is_null());
        assert!(queue.work_available.waiters.tail.is_null());
    }

    #[test]
    fn append_links_the_old_tail_and_preserves_new_work_link() {
        let mut queue = queue();
        let mut retained_successor = work(null_mut());
        let mut first = work(null_mut());
        let mut second = work(&mut retained_successor);
        queue.head = &mut first;
        queue.tail = &mut first;

        unsafe { class_8900_work_queue_enqueue(&mut queue, &mut second) };

        assert!(core::ptr::eq(queue.head, &mut first));
        assert!(core::ptr::eq(queue.tail, &mut second));
        assert!(core::ptr::eq(first.next, &mut second));
        assert!(core::ptr::eq(second.next, &mut retained_successor));
    }
}
