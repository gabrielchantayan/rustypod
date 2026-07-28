//! The two lazily-constructed application singletons:
//!
//! - `app_controller_get` — original: `FUN_0817ee04` @ 0x0817ee04
//!   (44 bytes; **1108 `bl` call sites**, binary-scanned — the hottest
//!   function in the whole mid region). Object size 0xE8, cached in the
//!   word at 0x089cc648 (the `+8` slot of the global @ 0x089cc640),
//!   constructed by `FUN_081847fc`.
//! - `app_screen_get` — original: `FUN_08173848` @ 0x08173848
//!   (44 bytes; 140 `bl` call sites). Object size 0x850, cached in the
//!   word at 0x089cc1bc, constructed by `FUN_08177a78`.
//!
//! Both are the same four-step idiom, and both `bl` the *same* ported
//! allocator:
//!
//! ```text
//! if (*slot == 0) { *slot = ctor(operator_new(SIZE)); }
//! return *slot;
//! ```
//!
//! `operator new` @ 0x082aadd4 is already ported
//! (`heap::veneers::operator_new`), so it is called directly. The two
//! constructors are not — they are large C++ ctors that wire the object
//! into the registry (`FUN_081847fc` looks a target up through the
//! manager @ 0x081883fc and vtable slot +0xe8) and build nested
//! sub-objects (`FUN_08177a78` chains eleven `FUN_0810ebbc` sub-ctors
//! and registers the result with class id 0x7800). They sit behind the
//! [`SINGLETON_CTORS`] dispatch table, the house pattern.
//!
//! What the objects are, from the call sites: the 0xE8 object is the
//! application controller — views hand themselves to it
//! (`FUN_08124af4(controller, view)`), callers poke a mode halfword at
//! its +0x80, and its ctor resolves a registry target. The 0x850 object
//! is the screen/layout side: callers load layout resources into it
//! (`FUN_08181110(screen, ...)` next to the "GotoExtraInfoLayout" /
//! "GotoGenius" literals, `FUN_08174300(screen, 0x80, ...)`) and then
//! hand it to the controller (`FUN_08183950(controller, screen)`). The
//! names follow that reading; neither class name survives in the image
//! (the ctor's name argument comes from a runtime global @ 0x080cb828).
//!
//! **These symbols are not hook-ready.** Until the two constructors are
//! ported, the dispatch defaults hand out a zeroed block — no vtable,
//! no registry wiring — so branching stock code here would break it.
//! The getters are ported because the *getter* logic (test, allocate,
//! construct, cache, reload) is fully recovered; the ctor slot is the
//! documented boundary.
//!
//! Faithful details:
//! - The cached word is re-loaded after construction rather than reused
//!   from the ctor's return (the original's second `ldr r0, [r4, #8]`).
//!   Observable if the ctor itself writes the slot.
//! - A ctor returning NULL caches NULL, so the next call re-allocates.
//!   Reproduced.
//! - The cache slots are the crate statics below rather than words at
//!   0x089cc648 / 0x089cc1bc (the block_mgr.rs deviation: that RW page
//!   is runtime-initialized; the image holds stale UI strings there).
//!   Both default to NULL, exactly the pre-init state.

use crate::heap::veneers::operator_new;

/// Allocation size of the application controller (`mov r0, #0xe8`).
pub const APP_CONTROLLER_SIZE: usize = 0xe8;

/// Allocation size of the screen object (`mov r0, #0x850`).
pub const APP_SCREEN_SIZE: usize = 0x850;

/// An ADS C++ constructor: takes the raw block, returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// Indirect dispatch table for the two unported constructors (see the
/// module header for the default-stub contract).
#[derive(Clone, Copy)]
pub struct SingletonCtors {
    /// Application-controller ctor @ 0x081847fc.
    pub app_controller: Constructor,
    /// Screen-object ctor @ 0x08177a78.
    pub app_screen: Constructor,
}

/// Default stub for the controller ctor: zeroes the block and returns
/// it. A faithful *subset* — both originals are dominated by zero
/// stores — but it installs no vtable and no registry wiring, which is
/// why the module header calls these symbols not hook-ready.
unsafe extern "C" fn zeroing_controller_ctor(this: *mut u8) -> *mut u8 {
    zero_block(this, APP_CONTROLLER_SIZE)
}

/// Default stub for the screen ctor: see [`zeroing_controller_ctor`].
unsafe extern "C" fn zeroing_screen_ctor(this: *mut u8) -> *mut u8 {
    zero_block(this, APP_SCREEN_SIZE)
}

/// Zeroes `size` bytes and returns the block. Volatile stores: a plain
/// loop is rewritten by LLVM into a call to `__aeabi_memclr`, a symbol
/// that does not exist in this build (the strcat.rs / surface.rs trap).
unsafe fn zero_block(this: *mut u8, size: usize) -> *mut u8 {
    if !this.is_null() {
        for offset in 0..size {
            this.add(offset).write_volatile(0);
        }
    }
    this
}

/// Wired defaults (documented zeroing stubs until the ctors are ported).
pub(crate) const DEFAULT_SINGLETON_CTORS: SingletonCtors = SingletonCtors {
    app_controller: zeroing_controller_ctor,
    app_screen: zeroing_screen_ctor,
};

/// The active constructors. Host tests install recording mocks; the
/// real ports replace the defaults when they exist.
pub static mut SINGLETON_CTORS: SingletonCtors = DEFAULT_SINGLETON_CTORS;

/// Reads one ctor slot (volatile — same rationale as every dispatch
/// table: the slot is meant to be swapped at runtime).
macro_rules! ctor {
    ($field:ident) => {
        core::ptr::read_volatile(core::ptr::addr_of!(SINGLETON_CTORS.$field))
    };
}

/// The application-controller singleton (original: the word @
/// 0x089cc648 — see the module-header deviation).
pub static mut APP_CONTROLLER: *mut u8 = core::ptr::null_mut();

/// The screen singleton (original: the word @ 0x089cc1bc).
pub static mut APP_SCREEN: *mut u8 = core::ptr::null_mut();

/// app_controller_get — original: `FUN_0817ee04` @ 0x0817ee04
/// (44 bytes).
///
/// Returns the application-controller singleton, constructing it on
/// first use.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_get() -> *mut u8 {
    let slot = core::ptr::addr_of_mut!(APP_CONTROLLER);
    if core::ptr::read_volatile(slot).is_null() {
        let block = operator_new(APP_CONTROLLER_SIZE);
        let object = (ctor!(app_controller))(block);
        core::ptr::write_volatile(slot, object);
    }
    core::ptr::read_volatile(slot)
}

/// app_screen_get — original: `FUN_08173848` @ 0x08173848 (44 bytes).
///
/// Returns the screen singleton, constructing it on first use.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_get() -> *mut u8 {
    let slot = core::ptr::addr_of_mut!(APP_SCREEN);
    if core::ptr::read_volatile(slot).is_null() {
        let block = operator_new(APP_SCREEN_SIZE);
        let object = (ctor!(app_screen))(block);
        core::ptr::write_volatile(slot, object);
    }
    core::ptr::read_volatile(slot)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes every test that swaps the globals below.
    static SINGLETON_LOCK: Mutex<()> = Mutex::new(());

    /// The block the stub allocator hands out (big enough for either
    /// singleton).
    static mut ARENA: [u8; APP_SCREEN_SIZE] = [0xa5; APP_SCREEN_SIZE];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Blocks handed to a constructor, in order.
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();

    /// What the recording constructors return (NULL means "fail").
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

    /// Installs the stub allocator plus recording constructors and
    /// clears both caches.
    fn mock(ctor_result: *mut u8) -> MutexGuard<'static, ()> {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            SINGLETON_CTORS = SingletonCtors {
                app_controller: recording_ctor,
                app_screen: recording_ctor,
            };
            CTOR_RESULT = ctor_result;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            APP_CONTROLLER = ptr::null_mut();
            APP_SCREEN = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            SINGLETON_CTORS = DEFAULT_SINGLETON_CTORS;
            APP_CONTROLLER = ptr::null_mut();
            APP_SCREEN = ptr::null_mut();
        }
        drop(guard);
    }

    fn arena() -> *mut u8 {
        unsafe { ptr::addr_of_mut!(ARENA) as *mut u8 }
    }

    /// A distinct address the recording ctors can return.
    fn constructed() -> *mut u8 {
        unsafe { arena().add(16) }
    }

    #[test]
    fn the_controller_is_allocated_at_its_exact_size_and_constructed_once() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(app_controller_get(), constructed());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0xe8]);
            assert_eq!(*ptr::addr_of!(CTOR_BLOCKS), std::vec![arena()]);
            assert_eq!(APP_CONTROLLER, constructed(), "the ctor result is cached");
        }
        restore(guard);
    }

    #[test]
    fn the_screen_is_allocated_at_its_exact_size() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(app_screen_get(), constructed());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0x850]);
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_returns_the_cache_without_allocating() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(app_controller_get(), constructed());
            assert_eq!(app_controller_get(), constructed());
            assert_eq!(app_controller_get(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated exactly once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn a_pre_seeded_cache_short_circuits_everything() {
        let guard = mock(constructed());
        unsafe {
            APP_CONTROLLER = arena().add(64);
            assert_eq!(app_controller_get(), arena().add(64));
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty());
            assert!((*ptr::addr_of!(CTOR_BLOCKS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_ctor_caches_null_and_the_next_call_retries() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(app_controller_get().is_null());
            assert!(APP_CONTROLLER.is_null());
            assert!(app_controller_get().is_null());
            assert_eq!(
                (*ptr::addr_of!(ALLOC_SIZES)).len(),
                2,
                "the original has no failure memory: it re-allocates every call"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_two_singletons_have_independent_caches() {
        let guard = mock(constructed());
        unsafe {
            app_controller_get();
            assert_eq!(APP_CONTROLLER, constructed());
            assert!(APP_SCREEN.is_null(), "the screen cache is untouched");
            app_screen_get();
            assert_eq!(APP_SCREEN, constructed());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![0xe8, 0x850]);
        }
        restore(guard);
    }

    #[test]
    fn the_getter_reloads_the_slot_after_construction() {
        // The original ends with a second `ldr r0, [r4, #8]`, so a ctor
        // that stores the slot itself wins over its own return value.
        unsafe extern "C" fn self_caching_ctor(this: *mut u8) -> *mut u8 {
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).push(this);
            APP_CONTROLLER = this.add(32);
            this.add(8) // deliberately different from what it stored
        }
        let guard = mock(ptr::null_mut());
        unsafe {
            SINGLETON_CTORS.app_controller = self_caching_ctor;
            // The getter's own store lands last, so its value is what
            // the reload sees.
            assert_eq!(app_controller_get(), arena().add(8));
            assert_eq!(APP_CONTROLLER, arena().add(8));
        }
        restore(guard);
    }

    #[test]
    fn the_default_ctor_stubs_zero_the_block_and_return_it() {
        let guard = SINGLETON_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = ptr::addr_of_mut!(ARENA) as *mut u8;
            for offset in 0..APP_SCREEN_SIZE {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_controller_ctor(block), block);
            for offset in 0..APP_CONTROLLER_SIZE {
                assert_eq!(block.add(offset).read(), 0, "byte +{offset:#x}");
            }
            assert_eq!(block.add(APP_CONTROLLER_SIZE).read(), 0xa5, "no overrun");

            assert_eq!(zeroing_screen_ctor(block), block);
            assert!((0..APP_SCREEN_SIZE).all(|offset| block.add(offset).read() == 0));

            assert!(zeroing_controller_ctor(ptr::null_mut()).is_null(), "NULL-safe");
        }
        restore(guard);
    }
}
