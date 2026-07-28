//! The six lazily-constructed framework singletons. Every one is the
//! same four-step idiom over its own cache word, its own allocation
//! size and its own constructor:
//!
//! ```text
//! if (*slot == 0) { *slot = ctor(operator_new(SIZE)); }
//! return *slot;
//! ```
//!
//! | address | name | size | cache | ctor | `bl` sites |
//! |---|---|---|---|---|---|
//! | 0x0817ee04 | [`app_controller_get`] | 0xe8 | 0x089cc648 | 0x081847fc | **1108** |
//! | 0x08173848 | [`app_screen_get`] | 0x850 | 0x089cc1bc | 0x08177a78 | 140 |
//! | 0x081eb0c4 | [`singleton_class_8900`] | 0x380 | 0x089cc3ac | 0x081ee0c0 | 88 |
//! | 0x0810a7b8 | [`singleton_class_6200`] | 0xd0 | 0x089cb308 | 0x0810ab3c | 47 |
//! | 0x081b803c | [`singleton_class_7f80`] | 0x1d4 | 0x089cc61c | 0x081b80b4 | 38 |
//! | 0x0816df60 | [`lazy_singleton_0x3c`] | 0x3c | 0x089d0130 | 0x0816e2ac | 38 |
//!
//! (Call-site counts binary-scanned; the earlier scouting notes said 86
//! / 38 / 37 / 36 for the bottom four.)
//!
//! `operator new` @ 0x082aadd4 is already ported
//! (`heap::veneers::operator_new`), so it is called directly. None of
//! the six constructors is — they are large C++ constructors — so they
//! sit behind the [`SINGLETON_CTORS`] dispatch table, the house
//! pattern.
//!
//! ## What the objects are
//!
//! - The 0xE8 object is the **application controller** — views hand
//!   themselves to it (`FUN_08124af4(controller, view)`), callers poke a
//!   mode halfword at its +0x80, and its ctor resolves a registry target
//!   through `demo_mode_instance` @ 0x081883fc and vtable slot +0xe8.
//! - The 0x850 object is the **screen/layout** side: callers load layout
//!   resources into it (`FUN_08181110(screen, ...)` next to the
//!   "GotoExtraInfoLayout" / "GotoGenius" literals,
//!   `FUN_08174300(screen, 0x80, ...)`) and then hand it to the
//!   controller (`FUN_08183950(controller, screen)`). Neither class name
//!   survives in the image (the ctor's name argument comes from a
//!   runtime global @ 0x080cb828).
//! - Three of the remaining four are identified only by the **class id**
//!   their constructor publishes into the by-id registry
//!   (`app/registry.rs`), which is the firmware's own name for them:
//!   0x8900 (registered @ 0x081ee0f0), 0x6200 (@ 0x0810ac1c — the id is
//!   set 22 instructions earlier, which is why an 8-instruction scan
//!   missed it) and 0x7f80 (@ 0x081b8194). **None of the three classes
//!   could be named**: unlike TCDemoMode/TCSportTimer/TRadioCntlr and
//!   friends, these constructors never hand a name to the class-name
//!   factory @ 0x0820b230, and no name literal sits anywhere in their
//!   bodies. The symbols therefore carry the id and nothing more —
//!   inventing "TCSomethingCntlr" would be worse than saying so.
//! - The 0x3c object registers nothing at all and has no name literal
//!   either, so only its size identifies it. Its constructor
//!   `FUN_0816e2ac` builds a small object with a flag byte at +0x10, a
//!   zeroed +0x14..+0x38 and a sub-object at +0x20.
//!
//! **None of these symbols is hook-ready.** Until the constructors are
//! ported, the dispatch defaults hand out a zeroed block — no vtable,
//! no registry wiring — so branching stock code here would break it.
//! The getters are ported because the *getter* logic (test, allocate,
//! construct, cache, reload) is fully recovered; the ctor slot is the
//! documented boundary.
//!
//! Faithful details:
//! - The cached word is re-loaded after construction rather than reused
//!   from the ctor's return (the original's second `ldr r0, [r4, #N]`).
//!   Observable if the ctor itself writes the slot.
//! - A ctor returning NULL caches NULL, so the next call re-allocates.
//!   Reproduced.
//! - The cache slots are the crate statics below rather than words in
//!   the 0x089cxxxx / 0x089dxxxx pages (the block_mgr.rs deviation:
//!   those RW pages are runtime-initialized; the image holds stale UI
//!   strings there). All six default to NULL, exactly the pre-init
//!   state.

use crate::heap::veneers::operator_new;

/// Allocation size of the application controller (`mov r0, #0xe8`).
pub const APP_CONTROLLER_SIZE: usize = 0xe8;

/// Allocation size of the screen object (`mov r0, #0x850`).
pub const APP_SCREEN_SIZE: usize = 0x850;

/// Allocation size of the registry-class-0x8900 singleton
/// (`mov r0, #0x380`).
pub const CLASS_8900_SIZE: usize = 0x380;

/// Allocation size of the registry-class-0x6200 singleton
/// (`mov r0, #0xd0`).
pub const CLASS_6200_SIZE: usize = 0xd0;

/// Allocation size of the registry-class-0x7f80 singleton
/// (`mov r0, #0x1d4`).
pub const CLASS_7F80_SIZE: usize = 0x1d4;

/// Allocation size of the unidentified 0x3c singleton
/// (`mov r0, #0x3c`).
pub const SINGLETON_0X3C_SIZE: usize = 0x3c;

/// An ADS C++ constructor: takes the raw block, returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// Indirect dispatch table for the six unported constructors (see the
/// module header for the default-stub contract).
#[derive(Clone, Copy)]
pub struct SingletonCtors {
    /// Application-controller ctor @ 0x081847fc.
    pub app_controller: Constructor,
    /// Screen-object ctor @ 0x08177a78.
    pub app_screen: Constructor,
    /// Registry-class-0x8900 ctor @ 0x081ee0c0.
    pub class_8900: Constructor,
    /// Registry-class-0x6200 ctor @ 0x0810ab3c.
    pub class_6200: Constructor,
    /// Registry-class-0x7f80 ctor @ 0x081b80b4.
    pub class_7f80: Constructor,
    /// The 0x3c object's ctor @ 0x0816e2ac.
    pub singleton_0x3c: Constructor,
}

/// Defines one default constructor stub: zeroes the block and returns
/// it. A faithful *subset* — every original is dominated by zero stores
/// — but it installs no vtable and no registry wiring, which is why the
/// module header calls these symbols not hook-ready.
macro_rules! zeroing_ctor {
    ($name:ident, $size:expr) => {
        unsafe extern "C" fn $name(this: *mut u8) -> *mut u8 {
            zero_block(this, $size)
        }
    };
}

zeroing_ctor!(zeroing_controller_ctor, APP_CONTROLLER_SIZE);
zeroing_ctor!(zeroing_screen_ctor, APP_SCREEN_SIZE);
zeroing_ctor!(zeroing_class_8900_ctor, CLASS_8900_SIZE);
zeroing_ctor!(zeroing_class_6200_ctor, CLASS_6200_SIZE);
zeroing_ctor!(zeroing_class_7f80_ctor, CLASS_7F80_SIZE);
zeroing_ctor!(zeroing_singleton_0x3c_ctor, SINGLETON_0X3C_SIZE);

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
    class_8900: zeroing_class_8900_ctor,
    class_6200: zeroing_class_6200_ctor,
    class_7f80: zeroing_class_7f80_ctor,
    singleton_0x3c: zeroing_singleton_0x3c_ctor,
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

/// The registry-class-0x8900 singleton (original: the word @
/// 0x089cc3ac, the `+4` slot of the global @ 0x089cc3a8).
pub static mut CLASS_8900_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x6200 singleton (original: the word @
/// 0x089cb308, the `+4` slot of the global @ 0x089cb304).
pub static mut CLASS_6200_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The registry-class-0x7f80 singleton (original: the word @
/// 0x089cc61c).
pub static mut CLASS_7F80_INSTANCE: *mut u8 = core::ptr::null_mut();

/// The unidentified 0x3c singleton (original: the word @ 0x089d0130,
/// the `+0xc` slot of the global @ 0x089d0124).
pub static mut SINGLETON_0X3C: *mut u8 = core::ptr::null_mut();

/// The body all six getters share: test the cache, allocate, construct,
/// store, and re-load the cache (the original's second `ldr r0, [r4,
/// #N]`, which is what makes a self-caching ctor observable).
///
/// The constructor arrives as a thunk so its dispatch-slot read stays
/// on the cold path, exactly where the original's `bl` is — passing the
/// pointer itself makes LLVM hoist the load above the cache test.
#[inline(always)]
unsafe fn lazy_singleton(
    cache: *mut *mut u8,
    size: usize,
    ctor: impl FnOnce() -> Constructor,
) -> *mut u8 {
    if core::ptr::read_volatile(cache).is_null() {
        let object = (ctor())(operator_new(size));
        core::ptr::write_volatile(cache, object);
    }
    core::ptr::read_volatile(cache)
}

/// app_controller_get — original: `FUN_0817ee04` @ 0x0817ee04
/// (44 bytes; 1108 `bl` call sites).
///
/// Returns the application-controller singleton, constructing it on
/// first use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(APP_CONTROLLER);
    lazy_singleton(cache, APP_CONTROLLER_SIZE, || unsafe { ctor!(app_controller) })
}

/// app_screen_get — original: `FUN_08173848` @ 0x08173848 (44 bytes;
/// 140 `bl` call sites).
///
/// Returns the screen singleton, constructing it on first use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_screen_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(APP_SCREEN);
    lazy_singleton(cache, APP_SCREEN_SIZE, || unsafe { ctor!(app_screen) })
}

/// singleton_class_8900 — original: `FUN_081eb0c4` @ 0x081eb0c4
/// (44 bytes; 88 `bl` call sites from 64 distinct callers).
///
/// The 0x380-byte singleton whose constructor publishes it in the by-id
/// class registry under id 0x8900 (`bl 0x081d23f8` @ 0x081ee0f0). The
/// class itself could not be named — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_8900() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_8900_INSTANCE);
    lazy_singleton(cache, CLASS_8900_SIZE, || unsafe { ctor!(class_8900) })
}

/// singleton_class_6200 — original: `FUN_0810a7b8` @ 0x0810a7b8
/// (44 bytes; 47 `bl` call sites).
///
/// The 0xd0-byte singleton registered under class id 0x6200
/// (`mov r1, #0x6200` @ 0x0810abc4, `bl 0x081d23f8` @ 0x0810ac1c). Its
/// constructor also parks the layout-resource names
/// "Menu_AboutID_Template_iPod_Layout",
/// "ResetAllSettings_Language_Layout" and
/// "DialogNotice_InsufficientDiskSpace_Layout" in the object, so it is
/// somewhere in the settings/about area — not enough to name the class.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_6200() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_6200_INSTANCE);
    lazy_singleton(cache, CLASS_6200_SIZE, || unsafe { ctor!(class_6200) })
}

/// singleton_class_7f80 — original: `FUN_081b803c` @ 0x081b803c
/// (44 bytes; 38 `bl` call sites).
///
/// The 0x1d4-byte singleton registered under class id 0x7f80
/// (`bl 0x081d23f8` @ 0x081b8194). Class not named — see the module
/// header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_class_7f80() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(CLASS_7F80_INSTANCE);
    lazy_singleton(cache, CLASS_7F80_SIZE, || unsafe { ctor!(class_7f80) })
}

/// lazy_singleton_0x3c — original: `FUN_0816df60` @ 0x0816df60
/// (44 bytes; 38 `bl` call sites).
///
/// The 0x3c-byte singleton. Unlike its three siblings this one's
/// constructor registers nothing and names nothing, so **its size is
/// the only identifying fact the firmware offers** and the symbol says
/// exactly that.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn lazy_singleton_0x3c() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(SINGLETON_0X3C);
    lazy_singleton(cache, SINGLETON_0X3C_SIZE, || unsafe { ctor!(singleton_0x3c) })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::HEAP_OPS;
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
                class_8900: recording_ctor,
                class_6200: recording_ctor,
                class_7f80: recording_ctor,
                singleton_0x3c: recording_ctor,
            };
            CTOR_RESULT = ctor_result;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            clear_caches();
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
            clear_caches();
        }
        drop(guard);
    }

    /// Resets every cache slot to its pre-init NULL.
    unsafe fn clear_caches() {
        APP_CONTROLLER = ptr::null_mut();
        APP_SCREEN = ptr::null_mut();
        CLASS_8900_INSTANCE = ptr::null_mut();
        CLASS_6200_INSTANCE = ptr::null_mut();
        CLASS_7F80_INSTANCE = ptr::null_mut();
        SINGLETON_0X3C = ptr::null_mut();
    }

    fn arena() -> *mut u8 {
        ptr::addr_of_mut!(ARENA) as *mut u8
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
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)), constructed(), "the ctor result is cached");
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
            assert!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)).is_null());
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
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)), constructed());
            assert!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)).is_null(), "the screen cache is untouched");
            app_screen_get();
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)), constructed());
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
            assert_eq!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)), arena().add(8));
        }
        restore(guard);
    }

    #[test]
    fn every_getter_allocates_its_own_size_and_caches_independently() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(singleton_class_8900(), constructed());
            assert_eq!(singleton_class_6200(), constructed());
            assert_eq!(singleton_class_7f80(), constructed());
            assert_eq!(lazy_singleton_0x3c(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![CLASS_8900_SIZE, CLASS_6200_SIZE, CLASS_7F80_SIZE, SINGLETON_0X3C_SIZE]
            );
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_8900_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_6200_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(CLASS_7F80_INSTANCE)), constructed());
            assert_eq!(ptr::read_volatile(ptr::addr_of!(SINGLETON_0X3C)), constructed());
            assert!(ptr::read_volatile(ptr::addr_of!(APP_CONTROLLER)).is_null(), "the other caches are untouched");
            assert!(ptr::read_volatile(ptr::addr_of!(APP_SCREEN)).is_null());
        }
        restore(guard);
    }

    #[test]
    fn the_original_allocation_sizes_are_the_literal_immediates() {
        assert_eq!(APP_CONTROLLER_SIZE, 0xe8);
        assert_eq!(APP_SCREEN_SIZE, 0x850);
        assert_eq!(CLASS_8900_SIZE, 0x380);
        assert_eq!(CLASS_6200_SIZE, 0xd0);
        assert_eq!(CLASS_7F80_SIZE, 0x1d4);
        assert_eq!(SINGLETON_0X3C_SIZE, 0x3c);
    }

    #[test]
    fn each_new_getter_constructs_exactly_once() {
        let guard = mock(constructed());
        unsafe {
            for _ in 0..3 {
                assert_eq!(singleton_class_8900(), constructed());
                assert_eq!(lazy_singleton_0x3c(), constructed());
            }
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 2);
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 2);
        }
        restore(guard);
    }

    #[test]
    fn a_null_returning_ctor_retries_on_every_new_getter() {
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(singleton_class_7f80().is_null());
            assert!(singleton_class_7f80().is_null());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![CLASS_7F80_SIZE, CLASS_7F80_SIZE],
                "no failure memory: it re-allocates every call"
            );
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
