//! Destroy a queued request and its owned polymorphic-owner array.
//!
//! `request_destroy` — original: `FUN_0818bc88` @ `0x0818bc88` (92 bytes,
//! 23 ARM words). Raw `osos.dec` establishes the exact extent from the push
//! at `0x0818bc88` through the pop at `0x0818bce0`; `0x0818bce4` is the
//! vtable literal and the next function starts at `0x0818bce8`. Four inbound
//! calls are plain unconditional `bl` instructions (`0x081d6170`,
//! `0x081f1b20`, `0x08267c9c`, and `0x08267cb8`); no predicated `bl` forms.
//!
//! Installs its destruction vtable, destroys the +0x48 subobject, virtual-
//! destroys every owner in the target-word vector at +0x38, frees that vector,
//! waits on the queue object at +0x04, and returns the original request.
//! Deliberate deviations: the two unrecovered direct callees retain typed
//! target-address seams; host tests install them explicitly.

use crate::cxx::polymorphic_owner_destroy::{polymorphic_owner_destroy, PolymorphicOwner};
use crate::heap::veneers::cxx_array_dealloc;

const REQUEST_DESTROY_VTABLE: u32 = 0x0898_9a00;
const RETAIL_SUBOBJECT_DESTROY: usize = 0x0818_cb08;
const RETAIL_QUEUE_WAIT: usize = 0x0821_596c;

type RequestSubobjectDestroy = unsafe extern "C" fn(*mut u32) -> *mut u32;
type QueueWait = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn destroy_subobject(subobject: *mut u32) -> *mut u32 {
    let destroy: RequestSubobjectDestroy = core::mem::transmute(RETAIL_SUBOBJECT_DESTROY);
    destroy(subobject)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn queue_wait(queue: *mut u32) -> *mut u32 {
    let wait: QueueWait = core::mem::transmute(RETAIL_QUEUE_WAIT);
    wait(queue)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct RequestDestroyOps {
    pub destroy_subobject: RequestSubobjectDestroy,
    pub queue_wait: QueueWait,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_destroy_subobject(subobject: *mut u32) -> *mut u32 { subobject }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_queue_wait(queue: *mut u32) -> *mut u32 { queue }
#[cfg(not(target_os = "none"))]
pub static mut REQUEST_DESTROY_OPS: RequestDestroyOps = RequestDestroyOps {
    destroy_subobject: host_destroy_subobject,
    queue_wait: host_queue_wait,
};

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn destroy_subobject(subobject: *mut u32) -> *mut u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(REQUEST_DESTROY_OPS.destroy_subobject)))(subobject)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn queue_wait(queue: *mut u32) -> *mut u32 {
    (core::ptr::read_volatile(core::ptr::addr_of!(REQUEST_DESTROY_OPS.queue_wait)))(queue)
}

/// Destroys the request object and returns `request`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn request_destroy(request: *mut u32) -> *mut u32 {
    request.write_volatile(REQUEST_DESTROY_VTABLE);
    let subobject = destroy_subobject(request.add(0x12));
    let begin = subobject.sub(4).read() as usize;
    let end = subobject.sub(3).read() as usize;
    let capacity = subobject.sub(2).read() as usize;
    let mut owner = begin;
    while owner != end {
        polymorphic_owner_destroy(owner as *mut PolymorphicOwner);
        owner += 4;
    }
    cxx_array_dealloc(begin as *mut u8, (capacity.wrapping_sub(begin)) >> 2, 0);
    queue_wait(subobject.sub(0x11)).sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static LOCK: Mutex<()> = Mutex::new(());
    static SUBOBJECT: AtomicUsize = AtomicUsize::new(0);
    static QUEUE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_subobject(pointer: *mut u32) -> *mut u32 {
        SUBOBJECT.store(pointer as usize, Ordering::Relaxed);
        pointer
    }
    unsafe extern "C" fn record_queue(pointer: *mut u32) -> *mut u32 {
        QUEUE.store(pointer as usize, Ordering::Relaxed);
        pointer
    }

    #[test]
    fn destroys_empty_request_in_target_word_layout() {
        let _lock = LOCK.lock();
        unsafe {
            let previous = REQUEST_DESTROY_OPS;
            REQUEST_DESTROY_OPS = RequestDestroyOps { destroy_subobject: record_subobject, queue_wait: record_queue };
            let mut request = [0u32; 32];
            SUBOBJECT.store(0, Ordering::Relaxed);
            QUEUE.store(0, Ordering::Relaxed);
            assert_eq!(request_destroy(request.as_mut_ptr()), request.as_mut_ptr());
            assert_eq!(request[0], REQUEST_DESTROY_VTABLE);
            assert_eq!(SUBOBJECT.load(Ordering::Relaxed), request.as_mut_ptr().add(0x12) as usize);
            assert_eq!(QUEUE.load(Ordering::Relaxed), request.as_mut_ptr().add(1) as usize);
            REQUEST_DESTROY_OPS = previous;
        }
    }
}
