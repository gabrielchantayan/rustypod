//! `class_8900_cached_property_6031` — original: `FUN_081ec268` @
//! `0x081ec268` (40 bytes; **17 `bl` call sites**, binary-verified by
//! decoding every B/BL word in osos.dec — all plain `bl`, no predicated
//! forms and no tail `b` sites, matching the scouting figure). Ghidra's
//! 40-byte extent is exact: the next function opens `push {r4, lr}` @
//! `0x081ec290`.
//!
//! A method of the registry-class-0x8900 object (the singleton from
//! `app/singletons.rs`'s `singleton_class_8900`; every call site hands
//! it the class-0x8c00 object's +0xd0 cache of that object — see
//! `app/class_8c00.rs`). The class-0x8900 ctor @ `0x081ee0c0` zeroes
//! +0x30 and stores `instance_of_class_6000()` at +0x378 (the last word
//! of the 0x380-sized object), so +0x30 is a cached property value and
//! +0x378 is the class-0x6000 store singleton the cache fronts:
//!
//! ```text
//! 081ec268  ldr  r1, [r0, #0x30]     @ cached = this->cached_6031
//! 081ec26c  cmp  r1, #0
//! 081ec270  ldreq  r0, [r0, #0x378]  @ cold: r0 = this->store
//! 081ec274  moveq  r2, #0x6000       @        arg3 = class id
//! 081ec278  ldreq  r1, [r0]          @        vtable = store->vtable
//! 081ec27c  ldreq  r3, [r1, #0xdc]   @        slot +0xdc
//! 081ec280  addeq  r1, r2, #0x31     @        arg2 = 0x6031
//! 081ec284  bxeq   r3                @ tail: read(store, 0x6031, 0x6000)
//! 081ec288  movne  r0, r1            @ warm: return cached
//! 081ec28c  bx     lr
//! ```
//!
//! So: return the cached value of state property **0x6031** when the
//! cache word is nonzero; otherwise query the class-0x6000 store through
//! its vtable slot **+0xdc** as `read(store, key, class_id)` — the same
//! calling convention as the sibling reader @ `0x08171fdc` (tail target
//! of `0x081115cc`), which dispatches slot **+0xe0** as
//! `read_typed(store, key, 0x6000, kind)` with kind `"Ui32"`
//! (0x55693332). r2 = 0x6000 is live into the tail call (set before the
//! key is formed from it), so it is a real third argument, not scratch.
//! Note the cold path does NOT write the answer back into +0x30 — the
//! cache is filled by somebody else; this getter only reads it.
//!
//! What 0x6031 IS is not named anywhere in the image, but the callers
//! pin its domain: the class-0x8c00 state-machine methods @
//! `0x081a5530`..`0x081a70d4` compare the result against the enum
//! constants 0x6032 / 0x6033 / 0x6038 / 0x603b (e.g. `case 0x6032`,
//! `case 0x6033` in the switch @ `0x081a5ab4`), i.e. property 0x6031 is
//! a mode/state word of the class-0x6000 0x60xx state family whose value
//! is itself one of the 0x60xx constants. Ghidra's decompile drops both
//! tail-call arguments ("Could not recover jumptable ... treating
//! indirect jump as call"); the listing above is the ground truth.
//!
//! ## Deviations
//!
//! - The receiver and the store are modeled as `#[repr(C)]` structs with
//!   native pointers (the `app/resource_chain.rs` precedent), so the
//!   decoded fields land on their original offsets on the 32-bit target
//!   (+0x30 / +0x378; vtable slot +0xdc = the 56th word) and the layout
//!   is self-consistent on the 64-bit test host.
//! - The original's loads are unguarded: a NULL +0x378 store (class
//!   0x6000 unregistered) faults in the original, and so does the port.
//! - The concrete class-0x6000 vtable is stock firmware and stays
//!   stock: the port performs the slot +0xdc dispatch itself, exactly
//!   like `resource_chain_find`'s inline `blx` through slot +0x64. No
//!   dispatch seam is needed — the callee is reached through the
//!   object's own vtable, so hooks that replace the object or its
//!   vtable are honored verbatim.

/// The property key this getter always binds (arg2 of the slot +0xdc
/// call; formed in the original as 0x6000 + 0x31).
const PROPERTY_KEY_6031: u32 = 0x6031;

/// The third argument of the class-0x6000 vtable read convention: the
/// owning class id (also the base the key is formed from).
const CLASS_ID_6000: u32 = 0x6000;

/// Vtable slot +0xdc of the class-0x6000 store: "read the current value
/// of state property `key`" (the untyped sibling of slot +0xe0, which
/// additionally takes a `"Ui32"`-style kind — see the module header).
pub type Class6000ReadFn =
    unsafe extern "C" fn(this: *mut Class6000, key: u32, class_id: u32) -> u32;

/// The class-0x6000 store vtable. Only slot +0xdc is decoded; the words
/// below it are named as a block so the decoded slot lands on its
/// original offset on the 32-bit target without any literal byte offset
/// (the `app/resource_chain.rs` `ResourceProviderVTable` pattern).
#[repr(C)]
pub struct Class6000VTable {
    /// Slots +0x00..+0xd8, not decoded by this port.
    pub slots_below: [Option<unsafe extern "C" fn()>; 55],
    /// Slot +0xdc.
    pub read: Class6000ReadFn,
}

/// The class-0x6000 store singleton, as seen through this getter: only
/// the vtable pointer is decoded.
#[repr(C)]
pub struct Class6000 {
    /// +0x00
    pub vtable: *const Class6000VTable,
}

/// The registry-class-0x8900 object, as seen through this getter: the
/// cached property value at +0x30 and the class-0x6000 store pointer at
/// +0x378 (the last word of the 0x380-sized object). Everything between
/// is the class's unported state.
#[repr(C)]
pub struct Class8900 {
    /// +0x00..+0x2c, not decoded by this port.
    pub state_below_cache: [u32; 12],
    /// +0x30 — cached value of property 0x6031; 0 = cold.
    pub cached_6031: u32,
    /// +0x34..+0x374, not decoded by this port.
    pub state_below_store: [u32; 209],
    /// +0x378 — the class-0x6000 store singleton (set by the ctor @
    /// `0x081ee0c0` from `instance_of_class_6000()`).
    pub store: *mut Class6000,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x30] = [0; core::mem::offset_of!(Class8900, cached_6031)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x378] = [0; core::mem::offset_of!(Class8900, store)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xdc] = [0; core::mem::offset_of!(Class6000VTable, read)];

/// class_8900_cached_property_6031 — original: `FUN_081ec268` @
/// `0x081ec268` (40 bytes).
///
/// Returns the cached value of state property 0x6031 when +0x30 is
/// nonzero; otherwise tail-dispatches the class-0x6000 store's vtable
/// slot +0xdc as `read(store, 0x6031, 0x6000)` and returns its answer
/// (which may itself be 0 — the cold path does not re-test).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_8900_cached_property_6031(this: *mut Class8900) -> u32 {
    let cached = (*this).cached_6031;
    if cached != 0 {
        return cached;
    }
    let store = (*this).store;
    let read = (*(*store).vtable).read;
    read(store, PROPERTY_KEY_6031, CLASS_ID_6000)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    /// What the slot +0xdc shim observed.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Call {
        store: *mut Class6000,
        key: u32,
        class_id: u32,
    }

    // The recorder is process-global because the vtable slot is a plain
    // `extern "C"` function pointer, exactly like the original's; the
    // tests in this module run under one lock.
    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: Vec<Call> = Vec::new();
    static mut ANSWER: u32 = 0;

    /// The scripted vtable slot +0xdc: records the call, answers
    /// [`ANSWER`].
    unsafe extern "C" fn scripted_read(
        store: *mut Class6000,
        key: u32,
        class_id: u32,
    ) -> u32 {
        CALLS.push(Call { store, key, class_id });
        ANSWER
    }

    const VTABLE: Class6000VTable = Class6000VTable {
        slots_below: [None; 55],
        read: scripted_read,
    };

    /// Builds the pair of fixture objects: a class-0x8900 receiver with
    /// `cached` at +0x30 and a class-0x6000 store behind the recording
    /// vtable.
    fn fixture(cached: u32) -> (Box<Class8900>, Box<Class6000>) {
        let mut store = Box::new(Class6000 { vtable: &VTABLE });
        let store_ptr = &mut *store as *mut Class6000;
        let this = Box::new(Class8900 {
            state_below_cache: [0; 12],
            cached_6031: cached,
            state_below_store: [0; 209],
            store: store_ptr,
        });
        (this, store)
    }

    /// Warm cache: the word at +0x30 is returned verbatim and the store
    /// is never touched — a NULL store must not fault, matching the
    /// original's `movne r0, r1; bx lr` path.
    #[test]
    fn warm_cache_returns_without_dispatch() {
        let _guard = TEST_LOCK.lock();
        unsafe { CALLS.clear() };
        let (mut this, _store) = fixture(0x6038);
        this.store = core::ptr::null_mut();
        let got = unsafe { class_8900_cached_property_6031(&mut *this) };
        assert_eq!(got, 0x6038);
        assert!(unsafe { CALLS.is_empty() }, "warm cache must not dispatch");
    }

    /// Every nonzero cache word is warm, including 1 and the enum
    /// constants the class-0x8c00 callers compare against.
    #[test]
    fn warm_cache_returns_verbatim_values() {
        let _guard = TEST_LOCK.lock();
        for cached in [1u32, 0x6032, 0x6033, 0x603b, u32::MAX] {
            unsafe { CALLS.clear() };
            let (mut this, _store) = fixture(cached);
            this.store = core::ptr::null_mut();
            assert_eq!(unsafe { class_8900_cached_property_6031(&mut *this) }, cached);
        }
        assert!(unsafe { CALLS.is_empty() });
    }

    /// Cold cache: the store's vtable slot +0xdc is dispatched exactly
    /// once with (store, 0x6031, 0x6000) and its answer propagates.
    #[test]
    fn cold_cache_dispatches_slot_dc_with_key_and_class() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALLS.clear();
            ANSWER = 0x603b;
        }
        let (mut this, store) = fixture(0);
        let store_ptr = &*store as *const Class6000 as *mut Class6000;
        let got = unsafe { class_8900_cached_property_6031(&mut *this) };
        assert_eq!(got, 0x603b);
        assert_eq!(
            unsafe { CALLS.clone() },
            [Call { store: store_ptr, key: 0x6031, class_id: 0x6000 }],
        );
    }

    /// A cold-cache answer of 0 propagates: the getter does not re-test
    /// or substitute the (still zero) cache word.
    #[test]
    fn cold_cache_zero_answer_propagates() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALLS.clear();
            ANSWER = 0;
        }
        let (mut this, _store) = fixture(0);
        assert_eq!(unsafe { class_8900_cached_property_6031(&mut *this) }, 0);
        assert_eq!(unsafe { CALLS.len() }, 1);
    }

    /// The query does not populate the cache: +0x30 is still 0 after a
    /// cold read, so a second call dispatches again.
    #[test]
    fn cold_cache_read_does_not_fill_cache() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CALLS.clear();
            ANSWER = 0x6033;
        }
        let (mut this, _store) = fixture(0);
        let first = unsafe { class_8900_cached_property_6031(&mut *this) };
        let second = unsafe { class_8900_cached_property_6031(&mut *this) };
        assert_eq!((first, second), (0x6033, 0x6033));
        assert_eq!(this.cached_6031, 0);
        assert_eq!(unsafe { CALLS.len() }, 2, "no caching in the getter");
    }
}
