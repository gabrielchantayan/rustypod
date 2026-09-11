//! `tagged_word_buffer_destroy` — destructor for the 20-byte tagged u32
//! buffer object.
//!
//! Original: `FUN_0803e5e4` @ 0x0803e5e4 (92 bytes exactly,
//! 0x0803e5e4..0x0803e640; the next independent body — the sibling key
//! comparator `FUN_0803e640` — starts immediately at 0x0803e640, so no
//! trailing literal pool is dropped). A full decode of every ARM B/BL word
//! in `osos.dec` finds 22 direct call sites, matching Ghidra's count: 14
//! unconditional `bl` plus 8 `blne` (all 8 at 0x080623cc..0x08062420, each
//! immediately preceded by `cmp r0, #0` — those callers NULL-check even
//! though the destructor has its own `movs`/`popeq` NULL guard). No `b`
//! tail calls target it.
//!
//! The object is five target words `{data, len, capacity, tag, flags}` —
//! the first three are exactly [`crate::heap::word_buffer::WordBuffer`];
//! the sibling comparator @ 0x0803e640 orders two objects by `tag` (a zero
//! tag sorts above any nonzero one), then by `len` (signed), then by an
//! unsigned lexicographic walk of the `data` u32 elements, which pins the
//! field layout. Destruction order:
//!
//! 1. NULL `this` returns immediately.
//! 2. If `data != NULL`: poison the buffer with the ported heap-poison
//!    helper [`crate::heap::heap_poison::heap_poison`](data, capacity << 2), then, unless
//!    `flags & FLAG_BUFFER_BORROWED`, release it through the ported
//!    `traced_free` @ 0x08043994. `FLAG_BUFFER_BORROWED` marks a buffer
//!    the object does not own.
//! 3. `flags` is RELOADED from the object (the original re-reads +0x10 at
//!    0x0803e618, after the buffer poison/free — a later flag store by
//!    either call is honored), bit 0 (`FLAG_DELETE_THIS`) is latched, and
//!    object itself is poisoned by `heap_poison(this, 20)`.
//! 4. If the latched bit was set, `this` is released through `traced_free`
//!    — the scalar-deleting-destructor bit. The original tail-branches
//!    (`bne 0x08043994`); the port makes an ordinary returning call, the
//!    same documented deviation as `traced_free`'s own post-trace branch.
//!
//! The poison helper is now a direct ported call. Its state byte is shared
//! with `traced_alloc` as [`crate::drivers::ata_cmd::LARGE_ALLOC_TAG`], so
//! the allocator marker and destructor scrub follow the one retailOS cell.

use crate::drivers::ata_cmd::{traced_alloc, traced_free};
use crate::heap::heap_poison::heap_poison;
use crate::kernel::diag_ring_record::diag_ring_record;

/// `flags` bit 0: release `this` itself through `traced_free` after the
/// object has been poisoned (scalar deleting destructor behavior).
pub const FLAG_DELETE_THIS: u32 = 1;
/// `flags` bit 1: the `data` buffer is borrowed — poison it but do not
/// release it.
pub const FLAG_BUFFER_BORROWED: u32 = 2;

/// Object size in bytes — the original poisons `this` with a literal 20
/// (0x0803e61c: `mov r1, #20`).
pub const TAGGED_WORD_BUFFER_SIZE: u32 = 20;

/// Target-layout tagged u32 buffer. Every field stays a target word so the
/// layout is 20 bytes on host and target alike; `data` is a target pointer
/// word, not a host pointer.
#[repr(C)]
pub struct TaggedWordBuffer {
    /// +0x00: element storage (target pointer word), NULL when empty.
    pub data: u32,
    /// +0x04: live element count (the comparator's signed length key).
    pub len: u32,
    /// +0x08: allocated element capacity; the destructor poisons
    /// `capacity << 2` bytes of `data`.
    pub capacity: u32,
    /// +0x0c: ordering tag (the comparator's primary key).
    pub tag: u32,
    /// +0x10: [`FLAG_DELETE_THIS`] / [`FLAG_BUFFER_BORROWED`].
    pub flags: u32,
}

/// tagged_word_buffer_create — original: `FUN_080403dc` @ 0x080403dc (92
/// bytes exactly, `0x080403dc..0x08040438`; the separately linked successor
/// begins at `0x08040438`).
///
/// Decoding every ARM B/BL immediate in `osos.dec` finds nine direct inbound
/// call sites, all unconditional `bl`: 0x0803dca0, 0x0803dcb0, 0x0803e2f0,
/// 0x0803e824, 0x0803eeb0, 0x0803f218, 0x0803fa00, 0x080e8b3c, and
/// 0x08368390. There are no predicated BL forms or direct tail branches.
///
/// Allocates a five-word buffer with `traced_alloc(20, 0, 0)`. Allocation
/// failure records diagnostic `(3, 0x71, 0x41, 0, 0)` and returns NULL.
/// Success initializes `{data, len, capacity, tag, flags}` to
/// `{0, 0, 0, 0, FLAG_DELETE_THIS}` in the retail store order
/// `flags, len, tag, capacity, data`, returning the self-deleting object.
///
/// Deliberate deviations: none. Both callees are ported, so this retains
/// direct calls rather than adding a dispatch seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_create() -> *mut TaggedWordBuffer {
    let buffer = traced_alloc(TAGGED_WORD_BUFFER_SIZE as i32, 0, 0).cast::<TaggedWordBuffer>();
    if buffer.is_null() {
        diag_ring_record(3, 0x71, 0x41, 0, 0);
        return core::ptr::null_mut();
    }

    // Volatile stores preserve the retail write order, visible to any
    // allocator instrumentation observing the newly returned block.
    core::ptr::addr_of_mut!((*buffer).flags).write_volatile(FLAG_DELETE_THIS);
    core::ptr::addr_of_mut!((*buffer).len).write_volatile(0);
    core::ptr::addr_of_mut!((*buffer).tag).write_volatile(0);
    core::ptr::addr_of_mut!((*buffer).capacity).write_volatile(0);
    core::ptr::addr_of_mut!((*buffer).data).write_volatile(0);
    buffer
}


/// tagged_word_buffer_destroy — original: `FUN_0803e5e4` @ 0x0803e5e4
/// (92 bytes; 14 `bl` + 8 `blne` call sites, all predicated sites
/// caller-side NULL checks).
///
/// Destroys the object as described in the module header. `this` must be
/// NULL or point at the five aligned writable target words above; a nonzero
/// `data` word released here (without [`FLAG_BUFFER_BORROWED`]) must be
/// owned by the allocation family paired with `traced_free`, as must `this`
/// itself when [`FLAG_DELETE_THIS`] is set.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tagged_word_buffer_destroy(this: *mut TaggedWordBuffer) {
    if this.is_null() {
        return;
    }
    let data = unsafe { core::ptr::addr_of!((*this).data).read_volatile() };
    if data != 0 {
        let capacity = unsafe { core::ptr::addr_of!((*this).capacity).read_volatile() };
        unsafe { heap_poison(data as usize as *mut u8, capacity << 2) };
        let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
        if flags & FLAG_BUFFER_BORROWED == 0 {
            unsafe { traced_free(data as usize as *mut u8) };
        }
    }
    // Re-read, not a reuse of the +0x10 load above: the original reloads
    // the flags word after the buffer poison/free (0x0803e618).
    let flags = unsafe { core::ptr::addr_of!((*this).flags).read_volatile() };
    let delete = flags & FLAG_DELETE_THIS;
    unsafe { heap_poison(this as *mut u8, TAGGED_WORD_BUFFER_SIZE) };
    if delete != 0 {
        unsafe { traced_free(this as *mut u8) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{
        TracedAllocHooks, TracedFreeHooks, LARGE_ALLOC_TAG, TRACED_ALLOC_HOOKS, TRACED_FREE_HOOKS,
    };
    use crate::kernel::diag_ring_record::{DiagEventRing, DIAG_RING_BLOCK_GETTER};
    use crate::testing::{DIAG_RING_TEST_LOCK, TRACED_ALLOC_TEST_LOCK};
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Calls reaching the free boundary, in execution order.
    static mut FREED: Vec<usize> = Vec::new();
    /// A buffer-free side effect the destructor's reload must observe.
    static mut FREE_SET_FLAGS: u32 = 0;
    static mut FLAG_TARGET: *mut u32 = core::ptr::null_mut();

    static mut ALLOC_RESULT: *mut u8 = core::ptr::null_mut();
    static mut ALLOC_REQUEST: Option<(i32, u32, u32)> = None;
    static mut DIAG_RING: *mut DiagEventRing = core::ptr::null_mut();

    unsafe extern "C" fn mock_free(block: *mut u8) {
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).push(block as usize);
            let set = FREE_SET_FLAGS;
            if set != 0 {
                *FLAG_TARGET |= set;
            }
        }
    }

    unsafe extern "C" fn recording_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        ALLOC_REQUEST = Some((size, tag1, tag2));
        ALLOC_RESULT
    }

    unsafe extern "C" fn ring_getter() -> *mut DiagEventRing {
        DIAG_RING
    }

    struct CreateFixture {
        _diag_guard: MutexGuard<'static, ()>,
        _alloc_guard: MutexGuard<'static, ()>,
        saved_alloc_hooks: TracedAllocHooks,
        saved_ring_getter: Option<unsafe extern "C" fn() -> *mut DiagEventRing>,
        storage: Box<[u32; 5]>,
        ring: Box<DiagEventRing>,
    }

    impl CreateFixture {
        fn new(allocation_succeeds: bool) -> Self {
            let diag_guard = DIAG_RING_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut storage = Box::new([0xa5a5_a5a5; 5]);
            let mut ring = Box::new(unsafe { core::mem::zeroed::<DiagEventRing>() });
            unsafe {
                ALLOC_REQUEST = None;
                ALLOC_RESULT = if allocation_succeeds {
                    storage.as_mut_ptr().cast::<u8>()
                } else {
                    core::ptr::null_mut()
                };
                DIAG_RING = ring.as_mut();
                let saved_alloc_hooks = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_ALLOC_HOOKS));
                let saved_ring_getter = core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_GETTER));
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS),
                    TracedAllocHooks { alloc: recording_alloc, trace: None },
                );
                core::ptr::write_volatile(core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER), Some(ring_getter));
                Self {
                    _diag_guard: diag_guard,
                    _alloc_guard: alloc_guard,
                    saved_alloc_hooks,
                    saved_ring_getter,
                    storage,
                    ring,
                }
            }
        }
    }

    impl Drop for CreateFixture {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS), self.saved_alloc_hooks);
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(DIAG_RING_BLOCK_GETTER),
                    self.saved_ring_getter,
                );
                ALLOC_RESULT = core::ptr::null_mut();
                ALLOC_REQUEST = None;
                DIAG_RING = core::ptr::null_mut();
            }
        }
    }

    fn install() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>, TracedFreeHooks, u8) {
        let alloc_guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let old_free = core::ptr::read_volatile(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            let old_tag = core::ptr::read_volatile(core::ptr::addr_of!(LARGE_ALLOC_TAG));
            TRACED_FREE_HOOKS = TracedFreeHooks { free: mock_free, trace: None };
            core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(0x61);
            (*core::ptr::addr_of_mut!(FREED)).clear();
            FREE_SET_FLAGS = 0;
            FLAG_TARGET = core::ptr::null_mut();
            (guard, alloc_guard, old_free, old_tag)
        }
    }

    unsafe fn restore(
        guard: MutexGuard<'static, ()>,
        alloc_guard: MutexGuard<'static, ()>,
        old_free: TracedFreeHooks,
        old_tag: u8,
    ) {
        unsafe {
            TRACED_FREE_HOOKS = old_free;
            core::ptr::addr_of_mut!(LARGE_ALLOC_TAG).write_volatile(old_tag);
        }
        drop(guard);
        drop(alloc_guard);
    }

    fn freed() -> Vec<usize> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    /// Writable buffer below 4 GiB so the u32 `data` word round-trips on
    /// host. Distinct hint; the mapper never unmaps, so no other module may
    /// reuse it.
    fn try_buffer() -> Option<*mut u8> {
        static SLAB: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::TAGGED_WORD_BUFFER, 0x1000)
                .map(|p| p as usize)
        });
        (*SLAB).map(|p| p as *mut u8)
    }

    fn fixture_unavailable() -> bool {
        try_buffer().is_none()
            && crate::testing::note_missing_u32_fixture("heap::tagged_word_buffer")
    }

    #[test]
    fn null_this_is_a_no_op() {
        let (guard, alloc_guard, old_free, old_tag) = install();
        unsafe { tagged_word_buffer_destroy(core::ptr::null_mut()) };
        assert!(freed().is_empty());
        assert_eq!(unsafe { core::ptr::addr_of!(LARGE_ALLOC_TAG).read_volatile() }, 0x61);
        unsafe { restore(guard, alloc_guard, old_free, old_tag) };
    }

    #[test]
    fn null_data_skips_buffer_release_but_poisons_and_deletes_self() {
        let (guard, alloc_guard, old_free, old_tag) = install();
        let mut object = TaggedWordBuffer { data: 0, len: 7, capacity: 9, tag: 3, flags: FLAG_DELETE_THIS };
        let this = &mut object as *mut TaggedWordBuffer;

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(freed(), std::vec![this as usize]);
        assert_ne!(unsafe { core::ptr::read_volatile(this.cast::<u8>()) }, 0,
            "the direct heap poison replaces the former no-op host seam");
        unsafe { restore(guard, alloc_guard, old_free, old_tag) };
    }

    #[test]
    fn null_data_without_delete_bit_only_poisons_self() {
        let (guard, alloc_guard, old_free, old_tag) = install();
        let mut object = TaggedWordBuffer { data: 0, len: 0, capacity: 0, tag: 0, flags: 0 };

        unsafe { tagged_word_buffer_destroy(&mut object) };

        assert!(freed().is_empty());
        assert_eq!(unsafe { core::ptr::read_volatile((&object as *const TaggedWordBuffer).cast::<u8>()) }, 0x61);
        unsafe { restore(guard, alloc_guard, old_free, old_tag) };
    }

    #[test]
    fn owned_buffer_is_poisoned_capacity_words_then_freed_before_self_poison() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old_free, old_tag) = install();
        let data = try_buffer().unwrap();
        unsafe { core::ptr::write_bytes(data, 0x11, 0x40) };
        let mut object = TaggedWordBuffer {
            data: data as usize as u32,
            len: 2,
            capacity: 3,
            tag: 0xdead,
            flags: 0,
        };
        let this = &mut object as *mut TaggedWordBuffer;

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(freed(), std::vec![data as usize]);
        assert_eq!(unsafe { core::ptr::read_volatile(data) }, 0x61,
            "the ported helper writes the current tag before advancing it");
        unsafe { restore(guard, alloc_guard, old_free, old_tag) };
    }

    #[test]
    fn borrowed_buffer_is_poisoned_but_never_freed() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old_free, old_tag) = install();
        let data = try_buffer().unwrap();
        let mut object = TaggedWordBuffer {
            data: data as usize as u32,
            len: 1,
            capacity: 4,
            tag: 0,
            flags: FLAG_BUFFER_BORROWED,
        };

        unsafe { tagged_word_buffer_destroy(&mut object) };

        assert!(freed().is_empty());
        assert_eq!(unsafe { core::ptr::read_volatile(data) }, 0x61);
        unsafe { restore(guard, alloc_guard, old_free, old_tag) };
    }

    #[test]
    fn flags_reloaded_after_buffer_release_honors_a_late_delete_bit() {
        if fixture_unavailable() {
            return;
        }
        let (guard, alloc_guard, old_free, old_tag) = install();
        let data = try_buffer().unwrap();
        let mut object = TaggedWordBuffer {
            data: data as usize as u32,
            len: 0,
            capacity: 1,
            tag: 0,
            flags: 0,
        };
        let this = &mut object as *mut TaggedWordBuffer;
        unsafe {
            FREE_SET_FLAGS = FLAG_DELETE_THIS;
            FLAG_TARGET = core::ptr::addr_of_mut!((*this).flags);
        }

        unsafe { tagged_word_buffer_destroy(this) };

        assert_eq!(freed(), std::vec![data as usize, this as usize],
            "the delete bit stored by the buffer free is seen: flags reload at 0x0803e618");
        unsafe { restore(guard, alloc_guard, old_free, old_tag) };
    }

    #[test]
    fn create_initializes_the_exact_five_word_object_after_allocation() {
        let fixture = CreateFixture::new(true);
        let buffer = unsafe { tagged_word_buffer_create() };

        assert_eq!(buffer.cast::<u32>(), fixture.storage.as_ptr().cast_mut());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((20, 0, 0)));
        assert_eq!(*fixture.storage, [0, 0, 0, 0, FLAG_DELETE_THIS]);
        assert_eq!(fixture.ring.head, 0);
    }

    #[test]
    fn create_records_allocation_failure_and_returns_null() {
        let fixture = CreateFixture::new(false);
        let buffer = unsafe { tagged_word_buffer_create() };

        assert!(buffer.is_null());
        assert_eq!(unsafe { ALLOC_REQUEST }, Some((20, 0, 0)));
        assert_eq!(fixture.ring.head, 1);
        assert_eq!(fixture.ring.tags[1], 0x0307_1041);
        assert_eq!(fixture.ring.data0[1], 0);
        assert_eq!(fixture.ring.data1[1], 0);
    }
}
