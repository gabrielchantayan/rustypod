//! Lazily-built event list of a retailOS view's event source object.
//!
//! Two halves of one protocol, ported from the pair @ 0x081e04b0 /
//! 0x081e054c:
//!
//! - [`event_list_acquire`] — original: `FUN_081e04b0` @ 0x081e04b0
//!   (44 bytes, 11 instructions; binary-scanned: **125 `bl` call sites**,
//!   no plain `b` tail-calls).
//! - [`event_list_release`] — original: `FUN_081e054c` @ 0x081e054c
//!   (80 bytes, 20 instructions; binary-scanned: **125 `bl` call sites**,
//!   no plain `b` tail-calls).
//!
//! # The object
//!
//! The source object embeds an ADS C++ `std::list` at +0x38 (28 bytes,
//! +0x38..+0x53) and a one-byte "list is built" flag at +0x54. Inside
//! that list, +0x10 is the circular sentinel node (`end()`), so the
//! source's +0x48 and the list's +0x10 are the same word — the original
//! loads it both ways in the same breath (`ldr r0, [r0, #72]` then
//! `ldr r0, [r1, #16]` after `add r1, r0, #56`), which is what pins the
//! embedded object's offset. A node's next pointer is at +0x8, so
//! `begin()` is `sentinel->next`. This is the same list flavour the
//! 0x083c1xxx runtime cluster operates on (sentinel at +0x10, node
//! count at +0x14), *not* the checked-iterator flavour cxx/list_splice.rs
//! ports (count at +0x10, next at +0x4).
//!
//! # The pairing
//!
//! Both halves have exactly 125 `bl` call sites and every caller uses
//! them as brackets around one consumer. The canonical site, the view
//! method @ 0x0839f838:
//!
//! ```text
//!   bl 0x081473c0     ; source = registry_lookup(view + 0xbc, key)
//!   mov r0, r6
//!   bl 0x081e04b0     ; list = event_list_acquire(source)
//!   mov r1, r0
//!   mov r0, r4
//!   bl 0x081346c8     ; view->member_list = *list  (list::operator=)
//!   mov r0, r6
//!   bl 0x081e054c     ; event_list_release(source)
//! ```
//!
//! So this is acquire / copy-out / release, not a lock: the source
//! builds its list on first use, hands it out by pointer, and the
//! release half throws the built list away again so the next acquire
//! rebuilds it against fresh registry state.
//!
//! `0x081346c8`'s callee `0x083c2130` is `list::operator=`, and its own
//! first act is byte-for-byte the argument marshalling `event_list_release`
//! performs — `erase(begin(), end())` on the destination — which is what
//! identifies [`EventListOps::erase_range`] as `std::list::erase(first,
//! last)` and the release half as a plain `clear()`.
//!
//! # What builds the list
//!
//! The build routine @ 0x081e0280 (548 bytes, unported) walks the source's
//! collection at +0x10 and resolves each element through the registry
//! returned by 0x0819fdb0, keyed by the ADS multi-character literals in
//! its pool: `'TEVT'` (0x54455654 @ 0x081e04a4) for the collection
//! elements and `'CEVT'` (0x43455654 @ 0x081e04ac) for the object at the
//! source's +0x58 — hence "event list". It appends each resolved 12-byte
//! descriptor to the very list at +0x38 that `event_list_acquire`
//! returns (`add r1, r4, #56` @ 0x081e03dc and 0x081e0478).
//!
//! # Deviations
//!
//! - The build @ 0x081e0280 and the list erase @ 0x083c1c3c are unported,
//!   so both go through the [`EVENT_LIST_OPS`] `read_volatile` dispatch
//!   seam (house pattern — see cxx/string_object.rs's
//!   `STRING_OBJECT_ASSIGN_CSTR_OPS`). Neither has a names.yaml entry, so
//!   neither may be called directly.
//! - The original's release frame is 24 bytes holding *two* copies of each
//!   iterator (sp+4 and sp+16 both hold `end()`, sp+8 and sp+20 both hold
//!   `begin()`) — ADS materializing the iterator temporaries twice. The
//!   port keeps one slot each, because `erase` only ever reads the pair
//!   handed to it in r2/r3.
//! - The original likewise loads the sentinel word twice (`ldr r0,
//!   [r0, #72]`, then `ldr r0, [r1, #16]`). The port loads it once; the
//!   two loads are of the same address with no intervening store.
//! - `event_list_acquire` returns `*mut u8` (the original's
//!   `add r0, r4, #56`); the list's layout stays opaque here, exactly as
//!   the original leaves it to `list::operator=`.

/// Byte offset of the embedded event list inside the source object
/// (original: `add r0, r4, #56` @ 0x081e04d4).
pub const EVENT_LIST_OFFSET: usize = 0x38;

/// Byte offset of the "list has been built" flag byte (original:
/// `ldrb r0, [r0, #84]` @ 0x081e04b8 and `strb r0, [r4, #84]` on both
/// halves).
pub const EVENT_LIST_BUILT_OFFSET: usize = 0x54;

/// Byte offset of the sentinel-node pointer inside a list object — the
/// list's `end()` (original: `ldr r0, [r1, #16]` @ 0x081e056c, the same
/// word the source reaches as `ldr r0, [r0, #72]` @ 0x081e0558).
pub const LIST_SENTINEL_OFFSET: usize = 0x10;

/// Byte offset of a node's next pointer; `begin()` is `sentinel->next`
/// (original: `ldr r0, [r0, #8]` @ 0x081e0560).
pub const NODE_NEXT_OFFSET: usize = 0x8;

/// Reads one u32 word of the opaque list/node layout. The fields are
/// 32-bit target pointers, so a host fixture backing them must sit below
/// 4 GiB (`crate::testing::try_map_u32_slab`). The read is aligned — both
/// offsets are word-aligned inside word-aligned objects, and the original
/// uses plain `ldr`; an unaligned read would expand to four `ldrb` on
/// ARMv5TE and stop matching.
#[inline(always)]
unsafe fn word(at: *const u8) -> u32 {
    unsafe { at.cast::<u32>().read() }
}

/// Explicit host-model boundary for the two unported callees of this pair.
#[derive(Clone, Copy)]
pub struct EventListOps {
    /// Original 0x081e0280: populate the source's event list from the
    /// registry. Runs exactly once per acquire/release cycle; the caller
    /// raises the built flag afterwards, so this routine owns nothing but
    /// the list contents.
    pub build: unsafe extern "C" fn(source: *mut u8),
    /// Original 0x083c1c3c: `std::list::erase(first, last)`. Writes the
    /// resulting iterator through `out` (the sret slot) and returns it.
    /// `first` and `last` are iterators — one-word slots holding node
    /// pointers, passed by address.
    pub erase_range: unsafe extern "C" fn(
        out: *mut u32,
        list: *mut u8,
        first: *mut u32,
        last: *mut u32,
    ) -> *mut u32,
}

/// Default boundary before 0x081e0280 is ported. Building the list needs
/// the registry the source resolves through, which does not exist on the
/// host; leaving the list empty is the honest stand-in and still exercises
/// the once-only flag protocol.
unsafe extern "C" fn missing_event_list_build(_source: *mut u8) {}

/// Default boundary before 0x083c1c3c is ported. The original's node
/// unlinking and its `*out` store both belong to that routine, so the
/// stand-in performs neither and just hands the sret slot back.
unsafe extern "C" fn missing_event_list_erase_range(
    out: *mut u32,
    _list: *mut u8,
    _first: *mut u32,
    _last: *mut u32,
) -> *mut u32 {
    out
}

/// Wired defaults for [`EVENT_LIST_OPS`].
pub const DEFAULT_EVENT_LIST_OPS: EventListOps = EventListOps {
    build: missing_event_list_build,
    erase_range: missing_event_list_erase_range,
};

/// Active model of the pair's two unported callees. Tests replace these
/// boundaries to observe the exact protocol; porting either callee later
/// replaces its default without touching the two halves below.
pub static mut EVENT_LIST_OPS: EventListOps = DEFAULT_EVENT_LIST_OPS;

#[inline(always)]
unsafe fn build_op() -> unsafe extern "C" fn(*mut u8) {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.build)) }
}

#[inline(always)]
unsafe fn erase_range_op(
) -> unsafe extern "C" fn(*mut u32, *mut u8, *mut u32, *mut u32) -> *mut u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EVENT_LIST_OPS.erase_range)) }
}

/// event_list_acquire — original: `FUN_081e04b0` @ 0x081e04b0 (44 bytes,
/// 125 `bl` call sites).
///
/// Builds the source's event list if the flag byte at +0x54 is clear, then
/// raises the flag, and returns the list at +0x38 either way. The flag is
/// tested as "non-zero means built", so a second acquire before the paired
/// [`event_list_release`] rebuilds nothing.
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

/// event_list_release — original: `FUN_081e054c` @ 0x081e054c (80 bytes,
/// 125 `bl` call sites).
///
/// Empties the source's event list with `erase(begin(), end())` and clears
/// the built flag, so the next [`event_list_acquire`] rebuilds. `end()` is
/// the list's sentinel node at +0x10 and `begin()` is that node's next
/// pointer at +0x8; both are read before the erase and passed to it by
/// address. The erase's returned iterator is discarded, as in the original.
///
/// The flag is cleared unconditionally — releasing a source that was never
/// acquired still runs the erase over an already-empty list, which is what
/// the original does.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_list_release(source: *mut u8) {
    let list = unsafe { source.add(EVENT_LIST_OFFSET) };
    let sentinel = unsafe { word(list.add(LIST_SENTINEL_OFFSET)) };
    let mut first = unsafe { word((sentinel as usize as *const u8).add(NODE_NEXT_OFFSET)) };
    let mut last = sentinel;
    let mut erased: u32 = 0;

    unsafe { (erase_range_op())(&mut erased, list, &mut first, &mut last) };
    unsafe { source.add(EVENT_LIST_BUILT_OFFSET).write(0) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Everything the mocked boundaries record, so a test can assert on the
    /// exact protocol rather than on side effects it invented itself.
    static mut BUILD_CALLS: u32 = 0;
    static mut BUILD_SOURCE: usize = 0;
    static mut ERASE_CALLS: u32 = 0;
    static mut ERASE_LIST: usize = 0;
    static mut ERASE_FIRST: u32 = 0;
    static mut ERASE_LAST: u32 = 0;

    unsafe extern "C" fn recording_build(source: *mut u8) {
        unsafe {
            BUILD_CALLS += 1;
            BUILD_SOURCE = source as usize;
        }
    }

    unsafe extern "C" fn recording_erase_range(
        out: *mut u32,
        list: *mut u8,
        first: *mut u32,
        last: *mut u32,
    ) -> *mut u32 {
        unsafe {
            ERASE_CALLS += 1;
            ERASE_LIST = list as usize;
            ERASE_FIRST = first.read();
            ERASE_LAST = last.read();
        }
        out
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
            ERASE_CALLS = 0;
            ERASE_LIST = 0;
            ERASE_FIRST = 0;
            ERASE_LAST = 0;
            EVENT_LIST_OPS = EventListOps {
                build: recording_build,
                erase_range: recording_erase_range,
            };
        }
        Bench { _lock: lock }
    }

    /// The source object, up to and including the flag byte. Only the
    /// acquire half is exercised through this — it never dereferences the
    /// list's pointer fields, so a plain host allocation is enough.
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

    /// Byte +0x54 is the only byte of the source the acquire half writes:
    /// the embedded list itself must come back untouched.
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

    /// The release half dereferences the list's sentinel word as a 32-bit
    /// target pointer, so its fixture must round-trip through `u32`.
    const SLAB_HINT: usize = 0x0d00_0000;
    const SLAB_LEN: usize = 0x1000;
    /// Where the sentinel node lives inside the slab, after the object.
    const SENTINEL_AT: usize = 0x100;
    /// Where the first element's node lives inside the slab.
    const FIRST_NODE_AT: usize = 0x200;

    /// One low mapping serves every release test; the `OPS_LOCK` each
    /// holds keeps them from sharing it concurrently (the
    /// heap/block_mgr.rs `try_slab` pattern).
    fn try_slab() -> Option<*mut u8> {
        use std::sync::OnceLock;
        static SLAB: OnceLock<Option<usize>> = OnceLock::new();
        (*SLAB.get_or_init(|| try_map_u32_slab(SLAB_HINT, SLAB_LEN).map(|p| p as usize)))
            .map(|p| p as *mut u8)
    }

    /// Builds a source object whose list at +0x38 has a sentinel at
    /// `SENTINEL_AT` linked to a single node at `FIRST_NODE_AT`. Returns
    /// the slab base, or `None` on a host that cannot map below 4 GiB.
    fn linked_source() -> Option<*mut u8> {
        let slab = try_slab()?;
        unsafe {
            core::ptr::write_bytes(slab, 0, SLAB_LEN);
            let sentinel = slab.add(SENTINEL_AT);
            let first = slab.add(FIRST_NODE_AT);
            slab.add(EVENT_LIST_OFFSET + LIST_SENTINEL_OFFSET)
                .cast::<u32>()
                .write(sentinel as usize as u32);
            sentinel
                .add(NODE_NEXT_OFFSET)
                .cast::<u32>()
                .write(first as usize as u32);
            slab.add(EVENT_LIST_BUILT_OFFSET).write(1);
        }
        Some(slab)
    }

    #[test]
    fn release_erases_begin_to_end_and_clears_the_flag() {
        let _bench = bench();
        let Some(slab) = linked_source() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };

        unsafe { event_list_release(slab) };

        assert_eq!(unsafe { ERASE_CALLS }, 1);
        assert_eq!(
            unsafe { ERASE_LIST },
            unsafe { slab.add(EVENT_LIST_OFFSET) } as usize,
            "the erase runs on the embedded list, not the source"
        );
        assert_eq!(
            unsafe { ERASE_FIRST },
            unsafe { slab.add(FIRST_NODE_AT) } as usize as u32,
            "first = sentinel->next = begin()"
        );
        assert_eq!(
            unsafe { ERASE_LAST },
            unsafe { slab.add(SENTINEL_AT) } as usize as u32,
            "last = the sentinel = end()"
        );
        assert_eq!(unsafe { slab.add(EVENT_LIST_BUILT_OFFSET).read() }, 0);
    }

    /// An empty list is the self-linked sentinel: `begin() == end()`. The
    /// original does not special-case it — it still calls the erase.
    #[test]
    fn release_of_an_empty_list_still_erases_with_begin_equal_to_end() {
        let _bench = bench();
        let Some(slab) = linked_source() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        let sentinel = unsafe { slab.add(SENTINEL_AT) };
        unsafe {
            sentinel
                .add(NODE_NEXT_OFFSET)
                .cast::<u32>()
                .write(sentinel as usize as u32)
        };

        unsafe { event_list_release(slab) };

        assert_eq!(unsafe { ERASE_CALLS }, 1);
        assert_eq!(unsafe { ERASE_FIRST }, sentinel as usize as u32);
        assert_eq!(unsafe { ERASE_LAST }, sentinel as usize as u32);
        assert_eq!(unsafe { slab.add(EVENT_LIST_BUILT_OFFSET).read() }, 0);
    }

    /// Releasing a never-acquired source is unguarded in the original: the
    /// erase runs and the already-clear flag is stored again.
    #[test]
    fn release_without_a_prior_acquire_is_unguarded() {
        let _bench = bench();
        let Some(slab) = linked_source() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        unsafe { slab.add(EVENT_LIST_BUILT_OFFSET).write(0) };

        unsafe { event_list_release(slab) };

        assert_eq!(unsafe { ERASE_CALLS }, 1, "no flag test gates the erase");
        assert_eq!(unsafe { slab.add(EVENT_LIST_BUILT_OFFSET).read() }, 0);
    }

    /// The caller-side contract the 125 paired call sites rely on: after a
    /// release the next acquire rebuilds.
    #[test]
    fn acquire_release_acquire_rebuilds() {
        let _bench = bench();
        let Some(slab) = linked_source() else {
            assert!(note_missing_u32_fixture("app::event_list"));
            return;
        };
        unsafe { slab.add(EVENT_LIST_BUILT_OFFSET).write(0) };

        let first_list = unsafe { event_list_acquire(slab) };
        unsafe { event_list_release(slab) };
        let second_list = unsafe { event_list_acquire(slab) };

        assert_eq!(first_list, second_list, "the list address never moves");
        assert_eq!(unsafe { BUILD_CALLS }, 2, "the release re-armed the build");
        assert_eq!(unsafe { ERASE_CALLS }, 1);
    }
}
