//! The service-manager singleton getter.
//!
//! `service_manager_get` — original: `FUN_081655e0` @ 0x081655e0 (52
//! bytes; the pool literal @ 0x08165614 holding &holder follows the
//! body). Reference: `decomp/c/014/081655e0_FUN_081655e0.c`;
//! definitive sequence: `decomp/osos.asm` @ 0x081655e0-0x08165610.
//!
//! 1 `bl` call site: 0x08258030, inside the boot-time singleton checker
//! `FUN_08258028` @ 0x08258028, which calls this getter first and then
//! nine sibling getters (0x08259740, 0x08257f34, 0x082598f8,
//! 0x08259564, 0x08257f04, 0x08259534, 0x0825a16c, 0x08259770),
//! falling into `heap_panic` unless every one returns non-NULL.
//!
//! Algorithm: the lazy-singleton idiom of the `app/singletons.rs`
//! family, over the holder struct @ 0x089ca948 whose layout
//! `app/service_manager.rs` documents —
//!
//! ```text
//! ldr r4, [0x08165614]   @ r4 = &holder (0x089ca948)
//! ldr r0, [r4, #4]       @ holder->instance
//! cmp r0, #0
//! bne done
//! mov r0, #0xe8
//! bl  0x082aadd4         @ operator_new(0xe8) — ported, called directly
//! bl  0x0816566c         @ service_manager_ctor — unported, dispatch slot
//! cmp r0, #0
//! str r0, [r4, #4]       @ cache unconditionally
//! bleq 0x08030f44        @ heap_panic — non-returning
//! done:
//! ldr r0, [r4, #4]       @ RELOAD the slot
//! pop {r4, pc}
//! ```
//!
//! Unlike the ten `app/singletons.rs` getters, a NULL constructor
//! result is fatal here: the original caches it and falls into
//! `heap_panic` @ 0x08030f44 (ported, `-> !`, called directly), so the
//! getter never returns NULL — matching the asserting accessor
//! `service_manager_instance` @ 0x08165520, whose own NULL check can
//! only fire before the first `service_manager_get` call.
//!
//! ## What the object is
//!
//! The **service-manager singleton** — the framework object that owns
//! retailOS's per-hardware subsystem handlers, fully documented by the
//! sibling module `app/service_manager.rs`: a 0xE8-byte C++ object
//! whose constructor @ 0x0816566c reads the hardware model id through
//! the settings/platform-info singleton (`FUN_08259928`, vtable slot
//! +0x34), indexes a 26-entry capability table by it (default mask
//! 0x1fbf @ 0x0816592c), builds up to thirteen subsystem handler
//! objects into the slot table at `this + 4`, and itself stores the
//! instance into the holder's +4 slot and sets the holder's +0/+1 flag
//! bytes. No class name survives in the image, so the symbol names the
//! role only. The constructor also writes the holder slot itself,
//! which is exactly what makes the getter's final slot RELOAD (rather
//! than reuse of the ctor's return) the faithful shape.
//!
//! ## Deviations (the app/singletons.rs / cxx/settings.rs contract)
//!
//! - The cache slot is the crate static
//!   [`SERVICE_MANAGER_INSTANCE`](crate::app::service_manager::SERVICE_MANAGER_INSTANCE)
//!   — owned by `app/service_manager.rs`, whose header names this
//!   getter as the publisher of that slot — rather than the word @
//!   0x089ca94c (holder +4): the 0x089caxxx pages are
//!   runtime-initialized and the image holds stale UI strings there.
//!   It defaults to NULL, exactly the pre-init state.
//! - The constructor @ 0x0816566c is unported (a large C++ constructor
//!   chaining the 0x08194228/0x08138ee8 sub-ctors, the capability-table
//!   walk and the per-slot handler builds), so it rides the
//!   [`SERVICE_MANAGER_CTOR`] dispatch slot with a documented zeroing
//!   stub default. `operator new` @ 0x082aadd4 is ported
//!   (`heap::veneers::operator_new`) and called directly.
//! - The fatal path is not exercised by the host tests: `heap_panic`
//!   is `-> !` and runs the raise/exit/terminate chain, so a host call
//!   cannot return (the `cxx/list_splice.rs` precedent, also recorded
//!   in `app/service_manager.rs`).
//!
//! **Not hook-ready**: until the constructor is ported the default
//! hands out a zeroed block — no vtable, no handler slot table — so
//! branching stock code at 0x081655e0 would break its caller.

use crate::app::service_manager::SERVICE_MANAGER_INSTANCE;
use crate::heap::veneers::{heap_panic, operator_new};
use core::ptr;

/// Allocation size of the service-manager object (`mov r0, #0xe8`).
pub const SERVICE_MANAGER_SIZE: usize = 0xe8;

/// An ADS C++ constructor: takes the raw block, returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// The default constructor stub: zeroes the block and returns it. A
/// faithful *subset* — the original is dominated by zero stores — but
/// it installs no vtable and no handler slot table, which is why the
/// module header calls this symbol not hook-ready. Volatile stores: a
/// plain loop is rewritten by LLVM into a call to `__aeabi_memclr`, a
/// symbol that does not exist in this build (the strcat.rs trap).
unsafe extern "C" fn zeroing_service_manager_ctor(this: *mut u8) -> *mut u8 {
    let mut cursor = this;
    let end = unsafe { this.add(SERVICE_MANAGER_SIZE) };
    while cursor < end {
        unsafe { ptr::write_volatile(cursor, 0) };
        cursor = unsafe { cursor.add(1) };
    }
    this
}

/// The active constructor (original: the direct `bl 0x0816566c`). Host
/// tests install a recording mock; the real port replaces the default
/// when it exists.
pub static mut SERVICE_MANAGER_CTOR: Constructor = zeroing_service_manager_ctor;

/// service_manager_get — original: `FUN_081655e0` @ 0x081655e0 (52
/// bytes; 1 `bl` call site).
///
/// Returns the service-manager singleton, constructing it on first
/// use: `operator_new(0xe8)` then the constructor @ 0x0816566c, caching
/// the ctor's return and RELOADING the slot before returning (the
/// original's second `ldr r0, [r4, #4]` — observable because the ctor
/// itself writes the slot). A NULL ctor result is cached and then
/// fatal: the original's `bleq 0x08030f44` runs [`heap_panic`], which
/// does not return, so this getter never hands out NULL.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn service_manager_get() -> *mut u8 {
    let cache = ptr::addr_of_mut!(SERVICE_MANAGER_INSTANCE);
    if unsafe { cache.read() }.is_null() {
        let block = unsafe { operator_new(SERVICE_MANAGER_SIZE) };
        // The slot read stays on the cold path, exactly where the
        // original's `bl` is — passing the pointer itself would let
        // LLVM hoist the load above the cache test.
        let ctor = unsafe { ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_CTOR)) };
        let constructed = unsafe { ctor(block) };
        unsafe { cache.write(constructed) };
        if constructed.is_null() {
            // `bleq 0x08030f44` — the original caches NULL and panics;
            // heap_panic never returns, so control cannot reach the
            // reload with a NULL cache.
            unsafe { heap_panic() };
        }
    }
    unsafe { cache.read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the globals below (the
    /// cxx/settings.rs SETTINGS_LOCK pattern).
    static SERVICE_MANAGER_LOCK: Mutex<()> = Mutex::new(());

    /// The block the stub allocator hands out.
    static mut ARENA: [u8; SERVICE_MANAGER_SIZE] = [0xa5; SERVICE_MANAGER_SIZE];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Blocks handed to the constructor, in order.
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();

    /// What the recording constructor returns.
    static mut CTOR_RESULT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        (*ptr::addr_of_mut!(ALLOC_SIZES)).push(size);
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    unsafe extern "C" fn recording_ctor(this: *mut u8) -> *mut u8 {
        (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
        ptr::read_volatile(ptr::addr_of!(CTOR_RESULT))
    }

    /// A non-NULL dummy heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached.
    static mut FAKE_HEAP: usize = 0;

    fn arena() -> *mut u8 {
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    /// A distinct address the recording ctor can return.
    fn constructed() -> *mut u8 {
        unsafe { arena().add(16) }
    }

    /// Installs the stub allocator plus the recording constructor and
    /// clears the cache.
    fn mock(ctor_result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = SERVICE_MANAGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            SERVICE_MANAGER_CTOR = recording_ctor;
            CTOR_RESULT = ctor_result;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            SERVICE_MANAGER_INSTANCE = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            SERVICE_MANAGER_CTOR = zeroing_service_manager_ctor;
            SERVICE_MANAGER_INSTANCE = ptr::null_mut();
        }
        drop(guard);
    }

    // The NULL-ctor-result path is deliberately untested: it caches
    // NULL and falls into heap_panic (`-> !`), which a host call
    // cannot survive — the cxx/list_splice.rs precedent.

    #[test]
    fn the_first_call_allocates_0xe8_constructs_and_caches() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(service_manager_get(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SERVICE_MANAGER_SIZE],
                "the `mov r0, #0xe8` immediate, allocated exactly once"
            );
            assert_eq!(
                *ptr::addr_of!(CTOR_BLOCKS),
                std::vec![arena()],
                "the ctor receives the raw operator_new block"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_INSTANCE)),
                constructed(),
                "the ctor result is cached in the holder slot"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_returns_the_cache_without_reallocating() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(service_manager_get(), constructed());
            assert_eq!(service_manager_get(), constructed());
            assert_eq!(service_manager_get(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed once");
        }
        restore(guard);
    }

    #[test]
    fn a_prepopulated_cache_is_returned_without_allocating() {
        // The `bne done` fast path: a non-NULL slot skips operator_new
        // and the ctor entirely.
        let guard = mock(constructed());
        unsafe {
            SERVICE_MANAGER_INSTANCE = constructed();
            assert_eq!(service_manager_get(), constructed());
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty(), "never allocated");
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty(), "never constructed");
        }
        restore(guard);
    }

    #[test]
    fn the_return_is_the_reloaded_slot_not_the_ctor_result() {
        // The original's final `ldr r0, [r4, #4]`: the getter returns
        // what the slot holds after the store. A ctor that returns a
        // different pointer than the block is fully propagated through
        // the cache — here the ctor returns constructed() while the
        // raw block was arena(), and both the cache and the return
        // carry constructed().
        let guard = mock(constructed());
        unsafe {
            let returned = service_manager_get();
            assert_eq!(returned, constructed());
            assert_ne!(returned, arena(), "the raw block is not returned");
            assert_eq!(ptr::read_volatile(ptr::addr_of!(SERVICE_MANAGER_INSTANCE)), returned);
        }
        restore(guard);
    }

    #[test]
    fn the_zeroing_default_ctor_clears_the_whole_block() {
        let guard = mock(ptr::null_mut());
        unsafe {
            let block = arena();
            assert_eq!(zeroing_service_manager_ctor(block), block);
            for offset in 0..SERVICE_MANAGER_SIZE {
                assert_eq!(*block.add(offset), 0, "byte {offset:#x} is zeroed");
            }
        }
        restore(guard);
    }
}
