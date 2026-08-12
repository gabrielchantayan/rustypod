//! The settings singleton getter.
//!
//! `settings_get` — original: `FUN_08259928` @ 0x08259928 (44 bytes;
//! 61 `bl` call sites). Reference: `decomp/c/025/08259928_FUN_08259928.c`;
//! definitive sequence: `decomp/osos.asm` @ 0x08259928-0x08259950.
//!
//! Algorithm: the same four-step lazy-singleton idiom as the
//! `app/singletons.rs` family —
//!
//! ```text
//! if (*slot == 0) { *slot = ctor(operator_new(0x84)); }
//! return *slot;   // re-loaded, not reused from the ctor's return
//! ```
//!
//! over the cache word @ 0x089cc948 (the pool literal @ 0x08259954 holds
//! its address), an allocation size of 0x84 (`mov r0, #0x84`), and the
//! constructor @ 0x08259eac.
//!
//! ## What the object is
//!
//! The firmware's **settings store**: an observable key-value object
//! whose virtual setters (the 0x08259970/0x082599d4/0x08259a64/0x08259da8/
//! 0x08259e18 family — no direct `bl` sites, so reached only through the
//! vtable) clamp small enum values, store them in byte fields, and post
//! change notifications 0x50009-0x50013 to the listener list the
//! constructor builds at +0x04 (dispatch through vtable slot +0x14).
//! A second string-keyed byte map lives at +0x40 (lookups @ 0x08259ac8/
//! 0x08259d24, writes @ 0x08259b3c, iteration @ 0x08259b5c), and
//! 0x08259e48 posts the 0x50001/0x50002 pair through slot +0x10. The
//! event consumer @ 0x08172744 is a settings view: it re-reads the
//! changed value through slots +0xc0..+0x108, repaints its rows
//! (resources 0x60bd/0x60f0-0x60f3), and mirrors the enum values into
//! the media-player interface (slot +0x30) — the repeat/shuffle-style
//! playback settings. The constructor plants primary vtable 0x089a75c8
//! at +0x00 — the same interface base the TPodMediaPlayer carries at
//! +0x14 — and the extended vtable 0x089a7b14 over it, and names nothing
//! (no class-name-factory call), so `settings` is the semantic name,
//! not a recovered class name.
//!
//! Deviations (the app/singletons.rs contract):
//! - The cache slot is the crate static [`SETTINGS_INSTANCE`] rather
//!   than the word @ 0x089cc948: those RW pages are runtime-initialized,
//!   and the image holds stale UI strings there. It defaults to NULL,
//!   exactly the pre-init state.
//! - The constructor @ 0x08259eac is unported (a 0x104-byte C++
//!   constructor chaining the 0x083c00dc/0x083b8a24 list+map node
//!   ctors), so it rides the [`SETTINGS_CTOR`] dispatch slot with a
//!   documented zeroing stub default. `operator new` @ 0x082aadd4 is
//!   ported (`heap::veneers::operator_new`) and called directly.
//!
//! **Not hook-ready**: until the constructor is ported the default hands
//! out a zeroed block — no vtable, no listener list — so branching stock
//! code at 0x08259928 would break it.

use crate::heap::veneers::operator_new;
use core::ptr;

/// Allocation size of the settings object (`mov r0, #0x84`).
pub const SETTINGS_SIZE: usize = 0x84;

/// An ADS C++ constructor: takes the raw block, returns `this`.
pub type Constructor = unsafe extern "C" fn(this: *mut u8) -> *mut u8;

/// The default constructor stub: zeroes the block and returns it. A
/// faithful *subset* — the original is dominated by zero stores — but it
/// installs no vtable and no listener list, which is why the module
/// header calls this symbol not hook-ready. Volatile stores: a plain
/// loop is rewritten by LLVM into a call to `__aeabi_memclr`, a symbol
/// that does not exist in this build (the strcat.rs trap).
unsafe extern "C" fn zeroing_settings_ctor(this: *mut u8) -> *mut u8 {
    let mut cursor = this;
    let end = unsafe { this.add(SETTINGS_SIZE) };
    while cursor < end {
        unsafe { ptr::write_volatile(cursor, 0) };
        cursor = unsafe { cursor.add(1) };
    }
    this
}

/// The active constructor (original: the direct `bl 0x08259eac`). Host
/// tests install a recording mock; the real port replaces the default
/// when it exists.
pub static mut SETTINGS_CTOR: Constructor = zeroing_settings_ctor;

/// The settings singleton (original: the word @ 0x089cc948, whose
/// address the pool literal @ 0x08259954 holds — see the module-header
/// deviation).
pub static mut SETTINGS_INSTANCE: *mut u8 = ptr::null_mut();

/// settings_get — original: `FUN_08259928` @ 0x08259928 (44 bytes;
/// 61 `bl` call sites).
///
/// Returns the settings-store singleton, constructing it on first use:
/// `operator_new(0x84)` then the constructor @ 0x08259eac, caching the
/// ctor's return and RELOADING the slot before returning (the original's
/// second `ldr r0, [r4, #0]` — observable if the ctor itself writes the
/// slot; a ctor returning NULL caches NULL, so the next call
/// re-allocates). Same NOT-HOOK-READY caveat as the app/singletons.rs
/// getters — see the module header.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn settings_get() -> *mut u8 {
    let cache = ptr::addr_of_mut!(SETTINGS_INSTANCE);
    if unsafe { cache.read() }.is_null() {
        let block = unsafe { operator_new(SETTINGS_SIZE) };
        // The slot read stays on the cold path, exactly where the
        // original's `bl` is — passing the pointer itself would let
        // LLVM hoist the load above the cache test.
        let ctor = unsafe { ptr::read_volatile(ptr::addr_of!(SETTINGS_CTOR)) };
        let constructed = unsafe { ctor(block) };
        unsafe { cache.write(constructed) };
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

    /// Serializes every test that swaps the globals below.
    static SETTINGS_LOCK: Mutex<()> = Mutex::new(());

    /// The block the stub allocator hands out.
    static mut ARENA: [u8; SETTINGS_SIZE] = [0xa5; SETTINGS_SIZE];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// Blocks handed to the constructor, in order.
    static mut CTOR_BLOCKS: Vec<*mut u8> = Vec::new();

    /// What the recording constructor returns (NULL means "fail").
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
        let guard = SETTINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            SETTINGS_CTOR = recording_ctor;
            CTOR_RESULT = ctor_result;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CTOR_BLOCKS)).clear();
            SETTINGS_INSTANCE = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            SETTINGS_CTOR = zeroing_settings_ctor;
            SETTINGS_INSTANCE = ptr::null_mut();
        }
        drop(guard);
    }

    #[test]
    fn the_first_call_allocates_0x84_constructs_and_caches() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(settings_get(), constructed());
            assert_eq!(
                *ptr::addr_of!(ALLOC_SIZES),
                std::vec![SETTINGS_SIZE],
                "the `mov r0, #0x84` immediate, allocated exactly once"
            );
            assert_eq!(
                *ptr::addr_of!(CTOR_BLOCKS),
                std::vec![arena()],
                "the ctor receives the raw operator_new block"
            );
            assert_eq!(
                ptr::read_volatile(ptr::addr_of!(SETTINGS_INSTANCE)),
                constructed(),
                "the ctor result is cached"
            );
        }
        restore(guard);
    }

    #[test]
    fn the_second_call_returns_the_cache_without_reallocating() {
        let guard = mock(constructed());
        unsafe {
            assert_eq!(settings_get(), constructed());
            assert_eq!(settings_get(), constructed());
            assert_eq!(settings_get(), constructed());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 1, "allocated once");
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 1, "constructed once");
        }
        restore(guard);
    }

    #[test]
    fn a_null_ctor_result_is_cached_and_retried() {
        // No failure memory: a NULL construct caches NULL, so the next
        // call takes the allocation path again.
        let guard = mock(ptr::null_mut());
        unsafe {
            assert!(settings_get().is_null());
            assert!(settings_get().is_null());
            assert_eq!((*ptr::addr_of!(ALLOC_SIZES)).len(), 2);
            assert_eq!((*ptr::addr_of!(CTOR_BLOCKS)).len(), 2);
        }
        restore(guard);
    }

    #[test]
    fn the_zeroing_default_ctor_clears_the_whole_block() {
        let guard = mock(ptr::null_mut());
        unsafe {
            let block = arena();
            assert_eq!(zeroing_settings_ctor(block), block);
            for offset in 0..SETTINGS_SIZE {
                assert_eq!(*block.add(offset), 0, "byte {offset:#x} is zeroed");
            }
        }
        restore(guard);
    }
}
