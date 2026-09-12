//! Directory-iterator teardown and its opaque queue boundaries.
//!
//! The iterator owns a 48-byte queue of pending directory entries and a
//! trailing [`StringObject`] path. Its queue helpers are still retailOS
//! boundaries; their target defaults call their verified fixed addresses and
//! host tests install recorders rather than assigning them identities.

use core::ptr;

use crate::app::path_probe::{FacadeFetch, FacadeObject, FacadeVtable, InterfaceGuard, PATH_PROBE_FACADE_FETCH};
use crate::cxx::string_object::{string_object_destroy_veneer, StringObject};
use crate::cxx::templates::container_is_empty;
#[cfg(target_os = "none")]
use crate::kernel::sync_mutex::counted_mutex_guard_acquire;
#[cfg(not(target_os = "none"))]
use crate::kernel::sync_mutex::mutex_lock_counted;
use crate::kernel::sync_mutex::{mutex_unlock_counted, CountedMutex};

/// Original literal-pool value at `0x081efa60`: the iterator's class vtable.
pub const DIRECTORY_ITERATOR_VTABLE: usize = 0x0898_ff40;
/// RetailOS queue-front helper called at `0x081efa0c`.
pub const DIRECTORY_ITERATOR_QUEUE_FRONT_ADDRESS: usize = 0x083d_df14;
/// RetailOS queue-pop helper called at `0x081efa28`.
pub const DIRECTORY_ITERATOR_QUEUE_POP_ADDRESS: usize = 0x083d_ff70;
/// RetailOS queue destructor called at `0x081efa50`.
pub const DIRECTORY_ITERATOR_QUEUE_DESTROY_ADDRESS: usize = 0x083d_e1b0;
/// RetailOS shared-base destructor tail called at `0x081efa58`.
pub const DIRECTORY_ITERATOR_BASE_DESTROY_ADDRESS: usize = 0x0818_a0fc;
/// Facade vtable slot loaded by `ldr r2,[r0,#0x44]` at `0x081efa18`.
pub const DIRECTORY_ITERATOR_RELEASE_SLOT_INDEX: usize = 0x44 / 4;

/// The opaque 48-byte target queue at iterator offset `+0x0c`.
#[repr(C)]
pub struct DirectoryIteratorQueue {
    pub words: [u32; 12],
}

/// The 68-byte directory iterator on ARM: a three-word shared base, then the
/// 48-byte entry queue and a two-word `StringObject` path at `+0x3c`.
/// Native-width pointer fields deliberately make the host model non-overlap.
#[repr(C)]
pub struct DirectoryIterator {
    pub vtable: usize,
    pub interface: *mut u8,
    pub base_flags: u32,
    pub queue: DirectoryIteratorQueue,
    pub path: StringObject,
}

/// The facade slot receives one queued entry's leading opaque pointer.
pub type DirectoryIteratorRelease = unsafe extern "C" fn(*mut FacadeObject, *mut u8);
pub type DirectoryIteratorQueueFront = unsafe extern "C" fn(*mut DirectoryIteratorQueue) -> *mut *mut u8;
pub type DirectoryIteratorQueuePop = unsafe extern "C" fn(*mut DirectoryIteratorQueue);
pub type DirectoryIteratorQueueDestroy = unsafe extern "C" fn(*mut DirectoryIteratorQueue) -> *mut DirectoryIteratorQueue;
pub type DirectoryIteratorBaseDestroy = unsafe extern "C" fn(*mut DirectoryIterator) -> *mut DirectoryIterator;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_queue_front(queue: *mut DirectoryIteratorQueue) -> *mut *mut u8 {
    let function: DirectoryIteratorQueueFront = core::mem::transmute(DIRECTORY_ITERATOR_QUEUE_FRONT_ADDRESS);
    function(queue)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_queue_front(_queue: *mut DirectoryIteratorQueue) -> *mut *mut u8 {
    ptr::null_mut()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_queue_pop(queue: *mut DirectoryIteratorQueue) {
    let function: DirectoryIteratorQueuePop = core::mem::transmute(DIRECTORY_ITERATOR_QUEUE_POP_ADDRESS);
    function(queue)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_queue_pop(_queue: *mut DirectoryIteratorQueue) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_queue_destroy(queue: *mut DirectoryIteratorQueue) -> *mut DirectoryIteratorQueue {
    let function: DirectoryIteratorQueueDestroy = core::mem::transmute(DIRECTORY_ITERATOR_QUEUE_DESTROY_ADDRESS);
    function(queue)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_queue_destroy(queue: *mut DirectoryIteratorQueue) -> *mut DirectoryIteratorQueue {
    queue
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_base_destroy(iterator: *mut DirectoryIterator) -> *mut DirectoryIterator {
    let function: DirectoryIteratorBaseDestroy = core::mem::transmute(DIRECTORY_ITERATOR_BASE_DESTROY_ADDRESS);
    function(iterator)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_base_destroy(iterator: *mut DirectoryIterator) -> *mut DirectoryIterator {
    iterator
}

/// Unported queue and base-destruction boundaries. The facade accessor is
/// already represented by `PATH_PROBE_FACADE_FETCH`, so this does not create
/// a duplicate seam for `0x0818a0bc`.
#[derive(Clone, Copy)]
pub struct DirectoryIteratorOps {
    pub queue_front: DirectoryIteratorQueueFront,
    pub queue_pop: DirectoryIteratorQueuePop,
    pub queue_destroy: DirectoryIteratorQueueDestroy,
    pub base_destroy: DirectoryIteratorBaseDestroy,
}

pub static mut DIRECTORY_ITERATOR_OPS: DirectoryIteratorOps = DirectoryIteratorOps {
    queue_front: firmware_queue_front,
    queue_pop: firmware_queue_pop,
    queue_destroy: firmware_queue_destroy,
    base_destroy: firmware_base_destroy,
};

#[inline(always)]
unsafe fn directory_iterator_ops() -> DirectoryIteratorOps {
    ptr::read_volatile(ptr::addr_of!(DIRECTORY_ITERATOR_OPS))
}

#[inline(always)]
unsafe fn facade_fetch() -> FacadeFetch {
    ptr::read_volatile(ptr::addr_of!(PATH_PROBE_FACADE_FETCH))
}

/// directory_iterator_destroy — original: `FUN_081ef9d8` @ `0x081ef9d8`
/// (132 instruction bytes plus the 4-byte literal-pool vtable; **8 direct
/// `bl` call sites**, all unconditional: `0x08093ffc`, `0x08100aec`,
/// `0x0813a4dc`, `0x0813ae84`, `0x081a2cf0`, `0x081d3ca4`, `0x081ee8dc`,
/// and `0x082752b4`; no predicated forms).
///
/// Reinstalls the directory-iterator vtable, holds the interface's counted
/// mutex, drains its pending-entry queue by invoking facade slot `+0x44` for
/// each entry's leading pointer, then releases the lock. It destroys the
/// trailing path, destroys the queue, and calls the shared-base teardown.
/// The queue/front/pop/base helpers remain fixed-address retailOS boundaries
/// on device and recorder seams on host because their class identities have
/// not been established. The already-ported mutex, string, empty-predicate,
/// and facade-accessor paths are called directly. Deliberate host-only
/// deviation: native pointers cannot be aligned at the target interface
/// lock's `+0x44` offset, so host reads that pointer unaligned before calling
/// the same ported lock routine.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn directory_iterator_destroy(
    iterator: *mut DirectoryIterator,
) -> *mut DirectoryIterator {
    (*iterator).vtable = DIRECTORY_ITERATOR_VTABLE;

    let mut lock: *mut CountedMutex = ptr::null_mut();
    #[cfg(target_os = "none")]
    counted_mutex_guard_acquire(
        ptr::addr_of_mut!(lock),
        iterator.cast::<*mut u8>() as *const *mut u8,
    );
    #[cfg(not(target_os = "none"))]
    {
        let interface = (*iterator).interface;
        lock = ptr::read_unaligned(interface.add(0x44).cast::<*mut CountedMutex>());
        mutex_lock_counted(lock);
    }

    let queue = ptr::addr_of_mut!((*iterator).queue);
    while container_is_empty(queue.cast()) == 0 {
        let facade = facade_fetch()(iterator.cast::<InterfaceGuard>(), 1);
        let vtable: *const FacadeVtable = ptr::read_volatile(ptr::addr_of!((*facade).vtable));
        let release: DirectoryIteratorRelease = core::mem::transmute(ptr::read_volatile(
            ptr::addr_of!((*vtable).slots[DIRECTORY_ITERATOR_RELEASE_SLOT_INDEX]),
        ));
        let entry = (directory_iterator_ops().queue_front)(queue);
        release(facade, ptr::read_volatile(entry));
        (directory_iterator_ops().queue_pop)(queue);
    }

    mutex_unlock_counted(lock);
    string_object_destroy_veneer(ptr::addr_of_mut!((*iterator).path));
    (directory_iterator_ops().queue_destroy)(queue);
    (directory_iterator_ops().base_destroy)(iterator)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::path_probe::tests::{restore_firmware_seams, PATH_PROBE_TEST_LOCK};
    use std::sync::MutexGuard;

    const EVENT_RELEASE_FIRST: u8 = 1;
    const EVENT_POP_FIRST: u8 = 2;
    const EVENT_RELEASE_SECOND: u8 = 3;
    const EVENT_POP_SECOND: u8 = 4;
    const EVENT_QUEUE_DESTROY: u8 = 5;
    const EVENT_BASE_DESTROY: u8 = 6;

    static mut EVENTS: [u8; 8] = [0; 8];
    static mut EVENT_COUNT: usize = 0;
    static mut QUEUE: *mut DirectoryIteratorQueue = ptr::null_mut();
    static mut ITEMS: [*mut u8; 2] = [ptr::null_mut(); 2];
    static mut FRONT_INDEX: usize = 0;
    static mut FACADE: *mut FacadeObject = ptr::null_mut();
    static mut MOCK_VTABLE: FacadeVtable = FacadeVtable { slots: [0; 24] };
    static mut MOCK_FACADE: FacadeObject = FacadeObject { vtable: ptr::null() };

    // A host pointer cannot be naturally aligned at the target's `+0x44`
    // address, so the fixture writes its lock pointer into raw target-layout
    // storage and the port reads it with `read_unaligned`.

    unsafe fn record(event: u8) {
        EVENTS[EVENT_COUNT] = event;
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn recording_fetch(
        _guard: *mut InterfaceGuard,
        selector: u32,
    ) -> *mut FacadeObject {
        assert_eq!(selector, 1);
        core::ptr::addr_of_mut!(MOCK_FACADE)
    }

    unsafe extern "C" fn recording_release(facade: *mut FacadeObject, item: *mut u8) {
        assert_eq!(facade, FACADE);
        let expected = ITEMS[FRONT_INDEX];
        assert_eq!(item, expected);
        record(if FRONT_INDEX == 0 { EVENT_RELEASE_FIRST } else { EVENT_RELEASE_SECOND });
    }

    unsafe extern "C" fn recording_front(queue: *mut DirectoryIteratorQueue) -> *mut *mut u8 {
        assert_eq!(queue, QUEUE);
        core::ptr::addr_of_mut!(ITEMS[FRONT_INDEX])
    }

    unsafe extern "C" fn recording_pop(queue: *mut DirectoryIteratorQueue) {
        assert_eq!(queue, QUEUE);
        record(if FRONT_INDEX == 0 { EVENT_POP_FIRST } else { EVENT_POP_SECOND });
        FRONT_INDEX += 1;
        if FRONT_INDEX == 2 {
            (*queue).words[8] = 0;
        }
    }

    unsafe extern "C" fn recording_queue_destroy(queue: *mut DirectoryIteratorQueue) -> *mut DirectoryIteratorQueue {
        assert_eq!(queue, QUEUE);
        record(EVENT_QUEUE_DESTROY);
        queue
    }

    unsafe extern "C" fn recording_base_destroy(iterator: *mut DirectoryIterator) -> *mut DirectoryIterator {
        record(EVENT_BASE_DESTROY);
        iterator
    }

    unsafe fn install_recording(iterator: *mut DirectoryIterator) {
        EVENTS = [0; 8];
        EVENT_COUNT = 0;
        QUEUE = ptr::addr_of_mut!((*iterator).queue);
        ITEMS = [0x1111usize as *mut u8, 0x2222usize as *mut u8];
        FRONT_INDEX = 0;
        let vtable = core::ptr::addr_of_mut!(MOCK_VTABLE);
        (*vtable).slots = [0; 24];
        (*vtable).slots[DIRECTORY_ITERATOR_RELEASE_SLOT_INDEX] = recording_release as usize;
        FACADE = core::ptr::addr_of_mut!(MOCK_FACADE);
        (*FACADE).vtable = vtable;
        ptr::addr_of_mut!(PATH_PROBE_FACADE_FETCH).write_volatile(recording_fetch);
        ptr::addr_of_mut!(DIRECTORY_ITERATOR_OPS).write_volatile(DirectoryIteratorOps {
            queue_front: recording_front,
            queue_pop: recording_pop,
            queue_destroy: recording_queue_destroy,
            base_destroy: recording_base_destroy,
        });
    }

    unsafe fn restore_ops() {
        ptr::addr_of_mut!(DIRECTORY_ITERATOR_OPS).write_volatile(DirectoryIteratorOps {
            queue_front: firmware_queue_front,
            queue_pop: firmware_queue_pop,
            queue_destroy: firmware_queue_destroy,
            base_destroy: firmware_base_destroy,
        });
    }

    fn take_lock() -> MutexGuard<'static, ()> {
        PATH_PROBE_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn destroys_each_pending_entry_under_the_counted_lock() {
        let _lock = take_lock();
        let mut interface_bytes = [0u8; 0x44 + core::mem::size_of::<*mut CountedMutex>()];
        let mut lock = CountedMutex {
            mutex: crate::kernel::sync_mutex::Mutex { sem_cell: ptr::null_mut(), unused: 0 },
            hold_count: 0,
        };
        unsafe {
            ptr::write_unaligned(
                interface_bytes.as_mut_ptr().add(0x44).cast::<*mut CountedMutex>(),
                ptr::addr_of_mut!(lock),
            );
        }
        let mut iterator = DirectoryIterator {
            vtable: 0,
            interface: interface_bytes.as_mut_ptr(),
            base_flags: 0,
            queue: DirectoryIteratorQueue { words: [0; 12] },
            path: StringObject { vtable: ptr::null(), payload: ptr::null_mut() },
        };
        iterator.queue.words[8] = 2;

        unsafe {
            install_recording(ptr::addr_of_mut!(iterator));
            let returned = directory_iterator_destroy(ptr::addr_of_mut!(iterator));
            assert_eq!(returned, ptr::addr_of_mut!(iterator));
            assert_eq!(iterator.vtable, DIRECTORY_ITERATOR_VTABLE);
            assert_eq!(lock.hold_count, 0, "the held count is released after draining");
            assert_eq!(&EVENTS[..EVENT_COUNT], &[EVENT_RELEASE_FIRST, EVENT_POP_FIRST, EVENT_RELEASE_SECOND, EVENT_POP_SECOND, EVENT_QUEUE_DESTROY, EVENT_BASE_DESTROY]);
            restore_ops();
            restore_firmware_seams();
        }
    }
}
