//! Lazily-built event list of a retailOS view's event source object.
//!
//! - [`event_list_acquire`] — original: `FUN_081e04b0` @ 0x081e04b0
//!   (44 bytes, 11 instructions; binary-scanned: **125 `bl` call sites**,
//!   no plain `b` tail-calls).
//!
//! # The object
//!
//! The source object embeds an ADS C++ `std::list` at +0x38 (28 bytes,
//! +0x38..+0x53) and a one-byte "list is built" flag at +0x54. The
//! accessor builds the list on first use, raises the flag, and returns
//! the list either way.
//!
//! # The protocol
//!
//! Every one of the 125 call sites brackets one consumer between this
//! accessor and the release half @ 0x081e054c, which has exactly the same
//! call count. The canonical site, the view method @ 0x0839f838:
//!
//! ```text
//!   bl 0x081473c0     ; source = registry_lookup(view + 0xbc, key)
//!   mov r0, r6
//!   bl 0x081e04b0     ; list = event_list_acquire(source)
//!   mov r1, r0
//!   mov r0, r4
//!   bl 0x081346c8     ; view->member_list = *list  (list::operator=)
//!   mov r0, r6
//!   bl 0x081e054c     ; release: clear the list, drop the built flag
//! ```
//!
//! So this is acquire / copy-out / release, not a lock: the source builds
//! its list on first use, hands it out by pointer, and the release half
//! throws it away again so the next acquire rebuilds against fresh
//! registry state.
//!
//! # What builds the list
//!
//! The build routine @ 0x081e0280 (548 bytes, unported) walks the source's
//! collection at +0x10 and resolves each element through the registry
//! returned by 0x0819fdb0, keyed by the ADS multi-character literals in
//! its pool: `'TEVT'` (0x54455654 @ 0x081e04a4) for the collection
//! elements and `'CEVT'` (0x43455654 @ 0x081e04ac) for the object at the
//! source's +0x58 — hence "event list". It appends each resolved 12-byte
//! descriptor to the very list at +0x38 this accessor returns
//! (`add r1, r4, #56` @ 0x081e03dc and 0x081e0478).
//!
//! # Deviations
//!
//! - The build @ 0x081e0280 is unported and has no names.yaml entry, so it
//!   goes through the [`EVENT_LIST_OPS`] `read_volatile` dispatch seam
//!   (house pattern — see cxx/string_object.rs's
//!   `STRING_OBJECT_ASSIGN_CSTR_OPS`) rather than being called directly.
//! - [`event_list_acquire`] returns `*mut u8` (the original's
//!   `add r0, r4, #56`); the list's layout stays opaque here, exactly as
//!   the original leaves it to `list::operator=`.

/// Byte offset of the embedded event list inside the source object
/// (original: `add r0, r4, #56` @ 0x081e04d4).
pub const EVENT_LIST_OFFSET: usize = 0x38;

/// Byte offset of the "list has been built" flag byte (original:
/// `ldrb r0, [r0, #84]` @ 0x081e04b8, `strb r0, [r4, #84]` @ 0x081e04d0).
pub const EVENT_LIST_BUILT_OFFSET: usize = 0x54;

/// Explicit host-model boundary for this pair's unported callees.
#[derive(Clone, Copy)]
pub struct EventListOps {
    /// Original 0x081e0280: populate the source's event list from the
    /// registry. Runs exactly once per acquire/release cycle; the caller
    /// raises the built flag afterwards, so this routine owns nothing but
    /// the list contents.
    pub build: unsafe extern "C" fn(source: *mut u8),
}

/// Default boundary before 0x081e0280 is ported. Building the list needs
/// the registry the source resolves through, which does not exist on the
/// host; leaving the list empty is the honest stand-in and still exercises
/// the once-only flag protocol.
unsafe extern "C" fn missing_event_list_build(_source: *mut u8) {}

/// Wired defaults for [`EVENT_LIST_OPS`].
pub const DEFAULT_EVENT_LIST_OPS: EventListOps = EventListOps {
    build: missing_event_list_build,
};

/// Active model of this pair's unported callees. Tests replace these
/// boundaries to observe the exact protocol; porting a callee later
/// replaces its default without touching the ports below.
pub static mut EVENT_LIST_OPS: EventListOps = DEFAULT_EVENT_LIST_OPS;

#[inline(always)]
unsafe fn build_op() -> unsafe extern "C" fn(*mut u8) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.build)) }
}

/// event_list_acquire — original: `FUN_081e04b0` @ 0x081e04b0 (44 bytes,
/// 125 `bl` call sites).
///
/// Builds the source's event list if the flag byte at +0x54 is clear, then
/// raises the flag, and returns the list at +0x38 either way. The flag is
/// tested as "non-zero means built", so a second acquire before the paired
/// release rebuilds nothing.
///
/// `source` is dereferenced unchecked, as in the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_acquire(source: *mut u8) -> *mut u8 {
    let built = unsafe { source.add(EVENT_LIST_BUILT_OFFSET) };
    if unsafe { built.read() } == 0 {
        unsafe { (build_op())(source) };
        unsafe { built.write(1) };
    }
    unsafe { source.add(EVENT_LIST_OFFSET) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Everything the mocked boundary records, so a test can assert on the
    /// exact protocol rather than on side effects it invented itself.
    static mut BUILD_CALLS: u32 = 0;
    static mut BUILD_SOURCE: usize = 0;

    unsafe extern "C" fn recording_build(source: *mut u8) {
        unsafe {
            BUILD_CALLS += 1;
            BUILD_SOURCE = source as usize;
        }
    }

    struct Bench {
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe { EVENT_LIST_OPS = DEFAULT_EVENT_LIST_OPS };
        }
    }

    fn bench() -> Bench {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            BUILD_CALLS = 0;
            BUILD_SOURCE = 0;
            EVENT_LIST_OPS = EventListOps { build: recording_build };
        }
        Bench { _lock: lock }
    }

    /// The source object, up to and including the flag byte. The accessor
    /// never dereferences the list's pointer fields, so a plain host
    /// allocation is enough.
    fn source_object() -> std::vec::Vec<u8> {
        std::vec![0u8; EVENT_LIST_BUILT_OFFSET + 1]
    }

    #[test]
    fn acquire_builds_once_and_raises_the_flag() {
        let _bench = bench();
        let mut object = source_object();
        let source = object.as_mut_ptr();

        let list = unsafe { event_list_acquire(source) };

        assert_eq!(list, unsafe { source.add(EVENT_LIST_OFFSET) });
        assert_eq!(unsafe { BUILD_CALLS }, 1);
        assert_eq!(unsafe { BUILD_SOURCE }, source as usize);
        assert_eq!(object[EVENT_LIST_BUILT_OFFSET], 1, "flag raised after the build");
    }

    #[test]
    fn acquire_on_a_built_source_skips_the_build_and_still_returns_the_list() {
        let _bench = bench();
        let mut object = source_object();
        object[EVENT_LIST_BUILT_OFFSET] = 1;
        let source = object.as_mut_ptr();

        let list = unsafe { event_list_acquire(source) };

        assert_eq!(list, unsafe { source.add(EVENT_LIST_OFFSET) });
        assert_eq!(unsafe { BUILD_CALLS }, 0, "the flag short-circuits the build");
        assert_eq!(object[EVENT_LIST_BUILT_OFFSET], 1, "the flag is left alone");
    }

    /// The test is `ldrb` + `cmp #0`, not `cmp #1` — any non-zero byte
    /// counts as built.
    #[test]
    fn acquire_treats_any_non_zero_flag_byte_as_built() {
        let _bench = bench();
        let mut object = source_object();
        object[EVENT_LIST_BUILT_OFFSET] = 0xff;
        let source = object.as_mut_ptr();

        unsafe { event_list_acquire(source) };

        assert_eq!(unsafe { BUILD_CALLS }, 0);
        assert_eq!(object[EVENT_LIST_BUILT_OFFSET], 0xff, "not normalized to 1");
    }

    /// Byte +0x54 is the only byte of the source the accessor writes: the
    /// embedded list itself must come back untouched.
    #[test]
    fn acquire_touches_no_byte_of_the_source_but_the_flag() {
        let _bench = bench();
        let mut object = source_object();
        for (index, byte) in object.iter_mut().enumerate() {
            *byte = index as u8;
        }
        object[EVENT_LIST_BUILT_OFFSET] = 0;
        let before = object.clone();
        let source = object.as_mut_ptr();

        unsafe { event_list_acquire(source) };

        assert_eq!(object[EVENT_LIST_BUILT_OFFSET], 1);
        assert_eq!(
            object[..EVENT_LIST_BUILT_OFFSET],
            before[..EVENT_LIST_BUILT_OFFSET],
            "the list bytes are the build routine's business, not ours"
        );
    }
}
