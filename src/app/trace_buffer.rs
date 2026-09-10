//! The trace-buffer local-static accessor.
//!
//! Port:
//! - [`trace_buffer_get`] — original: `FUN_0814a08c` @ `0x0814a08c`
//!   (**144-byte raw extent**: 128 bytes of code plus the four-word literal
//!   pool at `0x0814a10c..0x0814a118`; **20 unconditional `bl` call sites,
//!   no predicated `bl` forms or tail branches**, verified by decoding every
//!   ARM B/BL word in `osos.dec`).
//!
//! ## Stock algorithm
//!
//! ```text
//! if ((guard & 1) == 0 && cxa_guard_acquire(&guard) != 0) {
//!     condvar_init(trace_static_words);
//!     cxa_atexit(trace_static_words, 0x080ed318, __dso_handle);
//!     cxa_guard_release(&guard);
//! }
//! mutex_lock_counted(trace_static_words);
//! if (cached_buffer == NULL)
//!     cached_buffer = trace_buffer_construct(operator_new(0x40));
//! result = cached_buffer;
//! mutex_unlock_counted(trace_static_words);
//! return result;
//! ```
//!
//! The guard/cache pair is the page at `0x089cb1ec`/`+4`; the independently
//! addressed three words at `0x08a778e8` are initialized by
//! `condvar_init`. The function never reads its incoming r0 value, a fact
//! used by the registry fallback callers that leave a mismatch residue there.
//!
//! ## Deliberate deviations
//!
//! `FUN_0814a2c8`, the 0x40-byte buffer constructor, is not ported and is
//! therefore an explicit [`TRACE_BUFFER_CTOR`] seam with a zeroing default.
//! The literal destructor `0x080ed318` is not a function entry: raw ARM puts
//! it on `cmp r4,r6` inside the body beginning at `0x080ed2f0`. It cannot be
//! called with a valid shutdown callback frame, so the port registers a
//! no-op handler instead. On the 32-bit target the same three words are both
//! a `CondVar` and the counted-lock object. Host pointer widths make those
//! layouts differ, so host builds model the three target words directly while
//! preserving their initialize, lock-counter, and unlock-counter effects.

use core::ffi::c_void;

use crate::heap::veneers::operator_new;
use crate::app::facade_registry_walk::DEFAULT_ROOT_ACCESSOR_ADDRESS;
use crate::kernel::condvar::{condvar_init, condvar_wait_forever, CondVar};
use crate::kernel::sync_mutex::{
    mutex_lock, mutex_lock_counted, mutex_unlock, mutex_unlock_counted, CountedMutex, Mutex,
};
use crate::runtime::cxa_guard::{cxa_guard_acquire, cxa_guard_release};
use crate::runtime::shutdown_chain::cxa_atexit;

/// Allocation size passed to `operator_new` at `0x0814a0e8`.
pub const TRACE_BUFFER_SIZE: usize = 0x40;

/// Shared ADS `__dso_handle`, literal pool word at `0x0814a114`.
const DSO_HANDLE: i32 = 0x089c_a09c;

/// The local-static guard word at `0x089cb1ec`.
pub static mut TRACE_STATIC_GUARD: u32 = 0;

/// The cache word at `0x089cb1f0` (`0x089cb1ec + 4`).
pub static mut TRACE_BUFFER_CACHE: *mut u8 = core::ptr::null_mut();

/// The three words at `0x08a778e8`, directly modeled so their 32-bit target
/// layout remains meaningful on hosts with native-width pointers.
pub static mut TRACE_STATIC_WORDS: [u32; 3] = [0; 3];

/// Constructor ABI of `FUN_0814a2c8`: it receives an allocated 0x40-byte
/// block and returns the pointer which is cached verbatim.
pub type TraceBufferConstructor = unsafe extern "C" fn(block: *mut u8) -> *mut u8;

/// Host-safe stand-in for the not-yet-ported buffer constructor.
unsafe extern "C" fn zero_trace_buffer(block: *mut u8) -> *mut u8 {
    for offset in 0..TRACE_BUFFER_SIZE {
        block.add(offset).write_volatile(0);
    }
    block
}

/// Dispatch seam for the unported `FUN_0814a2c8` buffer constructor.
pub static mut TRACE_BUFFER_CTOR: TraceBufferConstructor = zero_trace_buffer;

/// The pool word at `0x0814a118` names `0x080ed318`, which is not callable.
unsafe extern "C" fn trace_static_destructor(_object: *mut c_void) {}

#[inline(always)]
unsafe fn trace_static_words() -> *mut u32 {
    core::ptr::addr_of_mut!(TRACE_STATIC_WORDS).cast::<u32>()
}

/// Executes the real target initializer without imposing a 32-bit C layout
/// on the host test process.
unsafe fn initialize_trace_static_words() {
    #[cfg(target_os = "none")]
    {
        condvar_init(trace_static_words().cast::<CondVar>());
    }

    #[cfg(not(target_os = "none"))]
    {
        TRACE_STATIC_WORDS = [0; 3];
    }
}

/// Locks the shared three-word object. The host path models the target's
/// `mutex_lock_counted` increment at word 2 after the lock has been acquired.
unsafe fn lock_trace_static_words() {
    #[cfg(target_os = "none")]
    {
        mutex_lock_counted(trace_static_words().cast::<CountedMutex>());
    }

    #[cfg(not(target_os = "none"))]
    {
        let hold_count = trace_static_words().add(2);
        hold_count.write_volatile(hold_count.read_volatile().wrapping_add(1));
    }
}

/// Unlocks the shared three-word object. The host path preserves the target's
/// decrement-before-signal ordering through the observable counter value.
unsafe fn unlock_trace_static_words() {
    #[cfg(target_os = "none")]
    {
        mutex_unlock_counted(trace_static_words().cast::<CountedMutex>());
    }

    #[cfg(not(target_os = "none"))]
    {
        let hold_count = trace_static_words().add(2);
        hold_count.write_volatile(hold_count.read_volatile().wrapping_sub(1));
    }
}

/// One registry entry returned through a trace-buffer slot.
///
/// The resolver only needs the counted mutex at +0x44. The first 17 target
/// words are deliberately opaque: different call sites use different
/// interface views over them.
#[repr(C)]
pub struct TraceBufferEntry {
    /// +0x00..+0x40 — opaque interface/root fields.
    pub opaque_00: [u32; 17],
    /// +0x44 — held by the caller through the output scope guard.
    pub access_lock: CountedMutex,
}

/// The 0x40-byte target registry built by the trace-buffer constructor.
///
/// Pointer-bearing fields are native-width on host; `repr(C)` gives every
/// documented offset on the 32-bit firmware target.
#[repr(C)]
pub struct TraceBuffer {
    /// +0x00..+0x18 — selector-indexed entry pointers.
    pub entries: [*mut TraceBufferEntry; 7],
    /// +0x1c — guards the entry table during selection.
    pub entries_lock: CountedMutex,
    /// +0x28 — nonzero after the constructor has published the table.
    pub initialized: u8,
    /// +0x29..+0x2b — aligns the condition mutex.
    pub initialized_padding: [u8; 3],
    /// +0x2c — condition-variable mutex.
    pub initialized_mutex: Mutex,
    /// +0x34 — waited on until `initialized` becomes nonzero.
    pub initialized_condvar: CondVar,
}

/// ABI of the unported ADS local-static accessor `FUN_0814a030`.
pub type TraceBufferDefaultEntryAccessor = unsafe extern "C" fn() -> *mut TraceBufferEntry;

#[cfg(target_os = "none")]
unsafe extern "C" fn default_trace_buffer_entry() -> *mut TraceBufferEntry {
    let accessor: TraceBufferDefaultEntryAccessor =
        core::mem::transmute(DEFAULT_ROOT_ACCESSOR_ADDRESS);
    accessor()
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn default_trace_buffer_entry() -> *mut TraceBufferEntry {
    core::ptr::null_mut()
}

/// Boundary for the registry's default-root accessor at `0x0814a030`.
///
/// That ADS local-static accessor is not yet ported. Device builds call its
/// verified fixed address; host tests install a concrete root to observe the
/// invalid-slot path.
pub static mut TRACE_BUFFER_DEFAULT_ENTRY_ACCESSOR: TraceBufferDefaultEntryAccessor =
    default_trace_buffer_entry;

#[inline(always)]
unsafe fn default_entry_accessor() -> TraceBufferDefaultEntryAccessor {
    core::ptr::read_volatile(core::ptr::addr_of!(TRACE_BUFFER_DEFAULT_ENTRY_ACCESSOR))
}

/// trace_buffer_get — original: `FUN_0814a08c` @ `0x0814a08c` (144-byte raw
/// extent: 128 code bytes plus a 16-byte literal pool).
///
/// Initializes the trace static once, then serializes lazy creation of its
/// 0x40-byte buffer. The constructor result is cached without a NULL guard:
/// a NULL result deliberately causes the next invocation to allocate and
/// construct again. The incoming r0 register is unused by the ARM body.
///
/// The fixed firmware globals are modeled as crate statics; the unported
/// constructor and invalid destructor-pool word use the deliberate seams
/// described in this module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trace_buffer_get")]
pub unsafe extern "C" fn trace_buffer_get() -> *mut u8 {
    let guard = core::ptr::addr_of_mut!(TRACE_STATIC_GUARD);
    if (guard.read_volatile() & 1) == 0 && cxa_guard_acquire(guard) != 0 {
        initialize_trace_static_words();
        cxa_atexit(
            trace_static_words().cast::<c_void>(),
            trace_static_destructor,
            DSO_HANDLE,
        );
        cxa_guard_release(guard);
    }

    lock_trace_static_words();
    let cache = core::ptr::addr_of_mut!(TRACE_BUFFER_CACHE);
    if cache.read_volatile().is_null() {
        let block = operator_new(TRACE_BUFFER_SIZE);
        cache.write_volatile(core::ptr::read_volatile(core::ptr::addr_of!(TRACE_BUFFER_CTOR))(block));
    }
    let result = cache.read_volatile();
    unlock_trace_static_words();
    result
}

/// trace_buffer_slot_acquire — original: `FUN_0814a130` @ `0x0814a130`
/// (144 bytes, next distinct function at `0x0814a1c0`).
///
/// The raw ARM holds the condition mutex at +0x2c until the byte at +0x28
/// becomes nonzero, takes the counted table mutex at +0x1c, and accepts only
/// selectors 0..6 with a non-NULL entry. A valid entry's counted mutex at
/// +0x44 is stored into `entry_guard` and acquired before the table mutex is
/// released; the caller owns that returned lock. An invalid selector or NULL
/// slot leaves `entry_guard` untouched and returns the default entry from the
/// ADS accessor `FUN_0814a030`.
///
/// Decoding every ARM B/BL word in `osos.dec` finds 11 unconditional `bl`
/// callers (0x08086988, 0x08086a08, 0x0808e100, 0x0809b660, 0x080a28c4,
/// 0x080ab06c, 0x080ab258, 0x080b5678, 0x080c6854, 0x080d9030, and
/// 0x0818a08c), no predicated forms, and one unconditional tail branch from
/// the forwarding wrapper at 0x08149f64. No aligned data word references this
/// address, so it is not a virtual dispatch target.
///
/// Deliberate deviations: the two unported one-word counted-lock guard
/// helpers (0x0818a128 and 0x08206e8c) are inlined through the existing
/// `mutex_lock_counted`/`mutex_unlock_counted` ports. The unported default
/// accessor remains a fixed-address device boundary with a host test seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trace_buffer_slot_acquire")]
pub unsafe extern "C" fn trace_buffer_slot_acquire(
    buffer: *mut TraceBuffer,
    selector: u32,
    entry_guard: *mut *mut CountedMutex,
) -> *mut TraceBufferEntry {
    mutex_lock(core::ptr::addr_of_mut!((*buffer).initialized_mutex));
    while (*buffer).initialized == 0 {
        condvar_wait_forever(core::ptr::addr_of_mut!((*buffer).initialized_condvar));
    }
    mutex_unlock(core::ptr::addr_of_mut!((*buffer).initialized_mutex));

    mutex_lock_counted(core::ptr::addr_of_mut!((*buffer).entries_lock));
    let entry = if selector < 7 {
        (*buffer).entries[selector as usize]
    } else {
        core::ptr::null_mut()
    };

    let result = if entry.is_null() {
        default_entry_accessor()()
    } else {
        let lock = core::ptr::addr_of_mut!((*entry).access_lock);
        entry_guard.write(lock);
        mutex_lock_counted(lock);
        entry
    };

    mutex_unlock_counted(core::ptr::addr_of_mut!((*buffer).entries_lock));
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, DEFAULT_HEAP_OPS, HEAP_OPS};
    use crate::runtime::shutdown_chain::{
        lib_shutdown_chain, shutdown_chain_head, ShutdownNode, SHUTDOWN_ALLOC, SHUTDOWN_FREE,
    };
    use core::ptr;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TRACE_BUFFER_LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATED_BLOCKS: Vec<*mut u8> = Vec::new();
    static mut CONSTRUCTED_BLOCKS: Vec<*mut u8> = Vec::new();
    static mut CTOR_RETURNS_NULL: bool = false;
    static mut DEFAULT_ENTRY_RESULT: *mut TraceBufferEntry = ptr::null_mut();
    static mut DEFAULT_ENTRY_CALLS: u32 = 0;

    unsafe extern "C" fn recording_default_entry() -> *mut TraceBufferEntry {
        DEFAULT_ENTRY_CALLS += 1;
        DEFAULT_ENTRY_RESULT
    }

    fn unlocked_counted_mutex() -> CountedMutex {
        CountedMutex {
            mutex: crate::kernel::sync_mutex::Mutex {
                sem_cell: ptr::null_mut(),
                unused: 0,
            },
            hold_count: 0,
        }
    }

    fn initialized_trace_buffer() -> TraceBuffer {
        TraceBuffer {
            entries: [ptr::null_mut(); 7],
            entries_lock: unlocked_counted_mutex(),
            initialized: 1,
            initialized_padding: [0; 3],
            initialized_mutex: crate::kernel::sync_mutex::Mutex {
                sem_cell: ptr::null_mut(),
                unused: 0,
            },
            initialized_condvar: unsafe { core::mem::zeroed() },
        }
    }

    fn trace_buffer_entry() -> TraceBufferEntry {
        TraceBufferEntry {
            opaque_00: [0; 17],
            access_lock: unlocked_counted_mutex(),
        }
    }

    fn default_entry_reset() {
        unsafe {
            DEFAULT_ENTRY_RESULT = ptr::null_mut();
            DEFAULT_ENTRY_CALLS = 0;
            TRACE_BUFFER_DEFAULT_ENTRY_ACCESSOR = default_trace_buffer_entry;
        }
    }

    fn default_entry_restore() {
        unsafe {
            TRACE_BUFFER_DEFAULT_ENTRY_ACCESSOR = default_trace_buffer_entry;
        }
    }

    #[test]
    fn slot_acquire_locks_selected_edge_entries_and_hands_out_their_guards() {
        let guard = reset();
        unsafe {
            let mut first = trace_buffer_entry();
            let mut last = trace_buffer_entry();
            let mut buffer = initialized_trace_buffer();
            buffer.entries[0] = ptr::addr_of_mut!(first);
            buffer.entries[6] = ptr::addr_of_mut!(last);
            let mut entry_guard = ptr::null_mut();

            assert_eq!(
                trace_buffer_slot_acquire(
                    ptr::addr_of_mut!(buffer),
                    0,
                    ptr::addr_of_mut!(entry_guard),
                ),
                ptr::addr_of_mut!(first),
            );
            assert_eq!(entry_guard, ptr::addr_of_mut!(first.access_lock));
            assert_eq!(first.access_lock.hold_count, 1, "returned guard remains acquired");
            assert_eq!(buffer.entries_lock.hold_count, 0, "table lock is released first");
            mutex_unlock_counted(entry_guard);

            assert_eq!(
                trace_buffer_slot_acquire(
                    ptr::addr_of_mut!(buffer),
                    6,
                    ptr::addr_of_mut!(entry_guard),
                ),
                ptr::addr_of_mut!(last),
            );
            assert_eq!(entry_guard, ptr::addr_of_mut!(last.access_lock));
            assert_eq!(last.access_lock.hold_count, 1, "selector six is in range");
            assert_eq!(buffer.entries_lock.hold_count, 0, "each lookup balances the table lock");
            mutex_unlock_counted(entry_guard);
        }
        restore(guard);
    }

    #[test]
    fn slot_acquire_uses_default_for_null_and_out_of_range_slots_without_touching_guard() {
        let guard = reset();
        unsafe {
            let mut fallback = trace_buffer_entry();
            let mut preserved_lock = unlocked_counted_mutex();
            let mut buffer = initialized_trace_buffer();
            DEFAULT_ENTRY_RESULT = ptr::addr_of_mut!(fallback);
            TRACE_BUFFER_DEFAULT_ENTRY_ACCESSOR = recording_default_entry;
            let mut entry_guard = ptr::addr_of_mut!(preserved_lock);

            assert_eq!(
                trace_buffer_slot_acquire(
                    ptr::addr_of_mut!(buffer),
                    3,
                    ptr::addr_of_mut!(entry_guard),
                ),
                ptr::addr_of_mut!(fallback),
                "a NULL in-range slot falls back",
            );
            assert_eq!(entry_guard, ptr::addr_of_mut!(preserved_lock));
            assert_eq!(
                trace_buffer_slot_acquire(
                    ptr::addr_of_mut!(buffer),
                    u32::MAX,
                    ptr::addr_of_mut!(entry_guard),
                ),
                ptr::addr_of_mut!(fallback),
                "unsigned bounds reject the largest selector",
            );
            assert_eq!(entry_guard, ptr::addr_of_mut!(preserved_lock));
            assert_eq!(DEFAULT_ENTRY_CALLS, 2);
            assert_eq!(buffer.entries_lock.hold_count, 0, "fallback releases the table lock");
        }
        restore(guard);
    }


    unsafe extern "C" fn trace_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        assert_eq!(size, TRACE_BUFFER_SIZE);
        assert_eq!(tag, 2, "operator_new's tag-2 allocation");
        let block = Box::into_raw(Box::new([0xa5; TRACE_BUFFER_SIZE])) as *mut u8;
        (*ptr::addr_of_mut!(ALLOCATED_BLOCKS)).push(block);
        block
    }

    unsafe extern "C" fn unused_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        _size: usize,
        _tag: usize,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn unused_free(
        _heap: *mut HeapDescriptorDescriptor,
        _block: *mut u8,
        _tag: usize,
    ) {}

    unsafe extern "C" fn unused_realloc(
        _heap: *mut HeapDescriptorDescriptor,
        _block: *mut u8,
        _size: usize,
        _a3: usize,
        _a4: usize,
    ) -> *mut u8 {
        ptr::null_mut()
    }

    unsafe extern "C" fn unused_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        ptr::null_mut()
    }

    unsafe extern "C" fn unused_new_handler(_code: usize) {}
    unsafe extern "C" fn unused_raise(_sig: i32, _code: i32) -> i32 { 0 }
    unsafe extern "C" fn unused_exit() {}
    unsafe extern "C" fn unused_terminate(_code: i32) {}

    const TRACE_HEAP_OPS: HeapVeneerOps = HeapVeneerOps {
        alloc: trace_alloc,
        alloc_zero: unused_alloc,
        free: unused_free,
        realloc: unused_realloc,
        create: unused_create,
        new_handler: unused_new_handler,
        raise: unused_raise,
        exit: unused_exit,
        terminate: unused_terminate,
    };

    unsafe extern "C" fn recording_ctor(block: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CONSTRUCTED_BLOCKS)).push(block);
        block.add(TRACE_BUFFER_SIZE - 1).write_volatile(0x5a);
        if CTOR_RETURNS_NULL { ptr::null_mut() } else { block }
    }

    unsafe extern "C" fn shutdown_alloc(size: usize) -> *mut u8 {
        assert_eq!(size, core::mem::size_of::<ShutdownNode>());
        Box::into_raw(Box::new(ShutdownNode {
            next: ptr::null_mut(),
            arg: ptr::null_mut(),
            handler: trace_static_destructor,
            key: 0,
        })) as *mut u8
    }

    unsafe extern "C" fn shutdown_free(block: *mut u8) {
        drop(Box::from_raw(block as *mut ShutdownNode));
    }

    fn reset() -> MutexGuard<'static, ()> {
        let guard = TRACE_BUFFER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            TRACE_STATIC_GUARD = 0;
            TRACE_BUFFER_CACHE = ptr::null_mut();
            TRACE_STATIC_WORDS = [0; 3];
            TRACE_BUFFER_CTOR = zero_trace_buffer;
            CTOR_RETURNS_NULL = false;
            (*ptr::addr_of_mut!(ALLOCATED_BLOCKS)).clear();
            (*ptr::addr_of_mut!(CONSTRUCTED_BLOCKS)).clear();
            HEAP_OPS = TRACE_HEAP_OPS;
            SHUTDOWN_ALLOC = shutdown_alloc;
            SHUTDOWN_FREE = shutdown_free;
            *shutdown_chain_head() = ptr::null_mut();
            default_entry_reset();
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            lib_shutdown_chain(0);
            for block in (*ptr::addr_of_mut!(ALLOCATED_BLOCKS)).drain(..) {
                drop(Box::from_raw(block as *mut [u8; TRACE_BUFFER_SIZE]));
            }
            HEAP_OPS = DEFAULT_HEAP_OPS;
            SHUTDOWN_ALLOC = crate::malloc_rt::malloc;
            SHUTDOWN_FREE = crate::malloc_rt::free;
            TRACE_BUFFER_CTOR = zero_trace_buffer;
            TRACE_STATIC_GUARD = 0;
            TRACE_BUFFER_CACHE = ptr::null_mut();
            default_entry_restore();
        }
        drop(guard);
    }

    #[test]
    fn first_call_initializes_registers_and_caches_constructor_result() {
        let guard = reset();
        unsafe {
            TRACE_BUFFER_CTOR = recording_ctor;
            let block = trace_buffer_get();
            assert!(!block.is_null(), "constructor result is cached and returned");
            assert_eq!(*ptr::addr_of!(TRACE_STATIC_GUARD), 1);
            assert_eq!(*ptr::addr_of!(TRACE_STATIC_WORDS), [0; 3], "balanced counted lock");
            assert_eq!(*ptr::addr_of!(CONSTRUCTED_BLOCKS), std::vec![block]);
            assert_eq!(block.add(TRACE_BUFFER_SIZE - 1).read(), 0x5a);

            let node = *shutdown_chain_head();
            assert!(!node.is_null(), "registered after static initialization");
            assert_eq!((*node).arg as *mut u32, trace_static_words());
            assert_eq!((*node).handler as usize, trace_static_destructor as usize);
            assert_eq!((*node).key, DSO_HANDLE);
            assert!((*node).next.is_null());
        }
        restore(guard);
    }

    #[test]
    fn cached_buffer_skips_allocation_and_construction() {
        let guard = reset();
        unsafe {
            TRACE_BUFFER_CTOR = recording_ctor;
            let first = trace_buffer_get();
            assert_eq!(trace_buffer_get(), first);
            assert_eq!(trace_buffer_get(), first);
            assert_eq!((*ptr::addr_of!(ALLOCATED_BLOCKS)).len(), 1);
            assert_eq!((*ptr::addr_of!(CONSTRUCTED_BLOCKS)).len(), 1);
            assert!((*(*shutdown_chain_head())).next.is_null(), "registered once");
        }
        restore(guard);
    }

    #[test]
    fn null_constructor_result_retries_on_each_call() {
        let guard = reset();
        unsafe {
            TRACE_BUFFER_CTOR = recording_ctor;
            CTOR_RETURNS_NULL = true;
            assert!(trace_buffer_get().is_null());
            assert!(trace_buffer_get().is_null());
            assert_eq!((*ptr::addr_of!(ALLOCATED_BLOCKS)).len(), 2);
            assert_eq!((*ptr::addr_of!(CONSTRUCTED_BLOCKS)).len(), 2);
            assert!((*(*shutdown_chain_head())).next.is_null(), "static still initializes once");
        }
        restore(guard);
    }

    #[test]
    fn bit_zero_clear_nonzero_guard_skips_static_initialization() {
        let guard = reset();
        unsafe {
            TRACE_STATIC_GUARD = 2;
            TRACE_STATIC_WORDS = [0, 0, 0x44];
            TRACE_BUFFER_CTOR = recording_ctor;
            assert!(!trace_buffer_get().is_null());
            assert_eq!(TRACE_STATIC_GUARD, 2, "acquire rejects the nonzero guard");
            assert_eq!(TRACE_STATIC_WORDS, [0, 0, 0x44], "lock bookkeeping balances");
            assert!(shutdown_chain_head().read().is_null(), "no registration after refusal");
            assert_eq!((*ptr::addr_of!(CONSTRUCTED_BLOCKS)).len(), 1, "cache remains independently lazy");
        }
        restore(guard);
    }
}
