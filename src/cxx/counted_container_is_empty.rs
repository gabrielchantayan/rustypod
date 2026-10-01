use crate::cxx::templates::container_is_empty;
use crate::kernel::sync_mutex::{CountedMutex, mutex_lock_counted, mutex_unlock_counted};

/// Container prefix with its counted mutex. On ARM the count is at +0x20
/// and the mutex is at +0x2c. Native pointer alignment may move the mutex
/// on a host; named fields keep the host fixture disjoint and aligned.
#[repr(C)]
pub struct CountedContainer {
    pub container_words: [u32; 11],
    pub lock: CountedMutex,
}

/// `counted_container_is_empty` — `FUN_0829e208` @ 0x0829e208.
///
/// True extent: 48 bytes, ending at 0x0829e238's independent literal-return
/// function. Raw branch decoding verifies two inbound plain BL calls, no
/// predicated inbound BL calls, and three plain outgoing BL calls (no
/// predicated outgoing calls): counted lock, emptiness query, counted unlock.
/// Acquire the mutex at +0x2c, test whether the word at +0x20 is exactly
/// zero, release the mutex, and return the saved 0/1 result.
/// Deliberate deviations: reuse the canonical `container_is_empty` port for
/// its byte-identical 0x083d75f0 alias; express layout with repr(C) for hosts.
///
/// LLVM inlines the counted acquire: the ARM output calls `mutex_lock`,
/// then increments +0x34; the predicate and counted release remain calls.
/// # Safety
/// `container` must point to a valid, exclusively accessible object until
/// the mutex is acquired, with a valid counted mutex and semaphore cell.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn counted_container_is_empty(container: *mut CountedContainer) -> u32 {
    let lock = core::ptr::addr_of_mut!((*container).lock);
    mutex_lock_counted(lock);
    let empty = container_is_empty(container.cast());
    mutex_unlock_counted(lock);
    empty
}
