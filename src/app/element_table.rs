//! The lazily-built **table of nine parallel object-slot arrays** and
//! the bounds-checked accessors that read out of it.
//!
//! `FUN_08105ffc` allocates one 0xd8-byte object on first use and
//! constructs nine sub-objects inside it, each 0x18 bytes and each with
//! the same arguments:
//!
//! ```text
//! r0 = operator_new(0xd8)
//! r0 = ctor0(r0,        0, 10, 2)      ; +0x00
//! r0 = ctor1(r0 + 0x18, 0, 10, 2)      ; +0x18
//! ...                                   ; nine in all
//! r0 = ctor8(r0 + 0x18, 0, 10, 2)      ; +0xc0
//! cache = r0 - 0xc0
//! ```
//!
//! 9 × 0x18 = 0xd8 exactly, and the nine constructors are nine
//! *different* addresses (0x083d3e8c, 0x083d4354, 0x083d40f0,
//! 0x083d3c28, 0x083d56b8, 0x083d51dc, 0x083d4cf4, 0x083d4a94,
//! 0x083d45b4) — nine instantiations of one container template, so the
//! nine arrays hold nine distinct element types. Each constructor lays
//! its sub-object out as
//!
//! ```text
//! +0x00  data      pointer to slot_count * 4 bytes, zero-filled
//! +0x04  slots     the argument 10 — the bound the accessors test
//! +0x08  0
//! +0x0c  the argument 0
//! +0x10  the argument 2 (a growth step)
//! +0x14  a second allocation
//! ```
//!
//! Nine accessors read them, one per array, all the same shape:
//!
//! | address | array | offset |
//! |---|---|---|
//! | 0x080f1038 | 0 | +0x00 |
//! | 0x080f0fb4 | 1 | +0x18 |
//! | 0x080f108c | 2 | +0x30 |
//! | 0x080f1060 | 3 | +0x48 |
//! | 0x080f100c | 4 | +0x60 |
//! | 0x080ed8fc | 5 | +0x78 |
//! | 0x080ed928 | 6 | +0x90 |
//! | 0x080ed8d0 | 7 | +0xa8 |
//! | 0x080f0fe0 | 8 | +0xc0 |
//!
//! This module ports the getter and the two busiest accessors —
//! 0x080ed928 (64 `bl`) and 0x080f1038 (47 `bl`), 111 sites across the
//! pair. The other seven are the same body with a different array
//! index and are one line each when someone wants them.
//!
//! **What the nine arrays hold is not identified.** The element type
//! only exists in the nine container constructors, which live at
//! 0x083d3xxx-0x083d5xxx (another agent's range) and carry no name — the
//! literal each one loads points into runtime data, not into a string.
//! The accessors are therefore named for the array they read, which is
//! all the firmware tells us. Their previous names in `names.yaml`
//! (`registry_entry_by_index` / `_alt`) were wrong: this table has
//! nothing to do with the by-id class registry in `app/registry.rs`.
//!
//! Faithful details:
//! - The getter runs *before* the bounds test, so even a negative index
//!   builds the table.
//! - The bound is `array.slots > index` with **signed** compares and a
//!   separate `index >= 0` test, so a negative index and
//!   `index == slots` both yield NULL. Reproduced exactly (the original
//!   leans on ARM predication: `cmp r4,#0` then `ldrge/cmpge` then
//!   `movle`/`ldrgt`).
//! - The cached pointer is the *last* constructor's return minus 0xc0,
//!   not the block `operator new` handed out, and each constructor's
//!   return feeds the next one's `+0x18`. Observable if a constructor
//!   returns anything but its `this`; reproduced.
//!
//! Deviations:
//! - The cache is the crate static [`ELEMENT_TABLE`] rather than the
//!   word @ 0x089ca3bc (the `block_mgr.rs` precedent: runtime-
//!   initialized RW). It defaults to NULL — the pre-init state.
//! - The nine constructors are unported and sit behind the
//!   [`ELEMENT_ARRAY_CTORS`] dispatch table, the house pattern, with
//!   documented zeroing stubs. With the stubs every array reports
//!   `slots = 0`, so every accessor returns NULL: safe, and honest
//!   about knowing nothing. **Not hook-ready** until the container
//!   constructors land.
//! - Sub-object and field offsets are computed by WORD INDEX rather
//!   than as literal byte offsets, so the 0x18 stride and the +0x00 /
//!   +0x04 fields are exact on the 32-bit target while a 64-bit host
//!   keeps them disjoint (the `block_region.rs` rule). The allocation
//!   size scales with them, so it is exactly the original's
//!   `mov r0, #0xd8` on target.

use crate::heap::veneers::operator_new;

/// Width of a pointer field: 4 on the ARMv5TE target (matching the
/// original layout), 8 on a 64-bit test host.
const WORD: usize = core::mem::size_of::<*mut u8>();

/// Sub-objects in the table (`0xd8 / 0x18`).
pub const ELEMENT_ARRAY_COUNT: usize = 9;

/// Words in one sub-object (0x18 bytes on target).
pub const ELEMENT_ARRAY_WORDS: usize = 6;

/// Byte stride between sub-objects (`add r0, r0, #0x18`).
pub const ELEMENT_ARRAY_STRIDE: usize = ELEMENT_ARRAY_WORDS * WORD;

/// Allocation size of the whole table (`mov r0, #0xd8`).
pub const ELEMENT_TABLE_SIZE: usize = ELEMENT_ARRAY_COUNT * ELEMENT_ARRAY_STRIDE;

// The size is the original's literal on the 32-bit target.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xd8] = [0; ELEMENT_TABLE_SIZE];

/// Slots every array is built with (`mov r2, #10`).
pub const ELEMENT_ARRAY_SLOTS: u32 = 10;

/// Growth step every array is built with (`mov r3, #2`).
pub const ELEMENT_ARRAY_GROWTH: u32 = 2;

/// The first constructor argument; every call site passes 0 and the
/// constructor parks it at the sub-object's +0x0c, which nothing ported
/// here reads.
pub const ELEMENT_ARRAY_OPTIONS: u32 = 0;

/// Word index of an array's slot buffer (byte offset 0x00).
const ARRAY_DATA_INDEX: usize = 0;

/// Word index of an array's slot count (byte offset 0x04) — the bound
/// the accessors test, and signed.
const ARRAY_SLOTS_INDEX: usize = 1;

/// One of the nine container constructors: takes the sub-object, returns
/// it (the ADS C++ convention the getter's `+0x18` chain relies on).
pub type ElementArrayCtor = unsafe extern "C" fn(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8;

/// Default stub for a container constructor: zeroes the sub-object and
/// returns it. A faithful *subset* — the real constructors also zero
/// the whole object — but it leaves `slots = 0`, so every accessor
/// reports NULL (see the module header).
///
/// Volatile stores: a plain loop is rewritten by LLVM into a call to
/// `__aeabi_memclr`, a symbol that does not exist in this build (the
/// `strcat.rs` / `singletons.rs` trap).
unsafe extern "C" fn zeroing_array_ctor(
    this: *mut u8,
    _options: u32,
    _slots: u32,
    _growth: u32,
) -> *mut u8 {
    if !this.is_null() {
        for offset in 0..ELEMENT_ARRAY_STRIDE {
            this.add(offset).write_volatile(0);
        }
    }
    this
}

/// Indirect dispatch table for the nine unported container constructors,
/// in the order the getter calls them (array 0 first).
pub type ElementArrayCtors = [ElementArrayCtor; ELEMENT_ARRAY_COUNT];

/// Wired defaults (documented zeroing stubs until the nine container
/// constructors — 0x083d3e8c, 0x083d4354, 0x083d40f0, 0x083d3c28,
/// 0x083d56b8, 0x083d51dc, 0x083d4cf4, 0x083d4a94, 0x083d45b4 — are
/// ported).
pub(crate) const DEFAULT_ELEMENT_ARRAY_CTORS: ElementArrayCtors =
    [zeroing_array_ctor; ELEMENT_ARRAY_COUNT];

/// The active constructors. Host tests install recording mocks; the
/// real ports replace the defaults when they exist.
pub static mut ELEMENT_ARRAY_CTORS: ElementArrayCtors = DEFAULT_ELEMENT_ARRAY_CTORS;

/// The cached table (original: the word @ 0x089ca3bc — see the
/// module-header deviation).
pub static mut ELEMENT_TABLE: *mut u8 = core::ptr::null_mut();

/// element_table — original: `FUN_08105ffc` @ 0x08105ffc (224 bytes;
/// 38 `bl` call sites).
///
/// The table of nine object-slot arrays, built on first use.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_table() -> *mut u8 {
    let slot = core::ptr::addr_of_mut!(ELEMENT_TABLE);
    if core::ptr::read_volatile(slot).is_null() {
        let mut cursor = operator_new(ELEMENT_TABLE_SIZE);
        for array in 0..ELEMENT_ARRAY_COUNT {
            if array != 0 {
                cursor = cursor.add(ELEMENT_ARRAY_STRIDE);
            }
            let ctor = core::ptr::read_volatile(core::ptr::addr_of!(ELEMENT_ARRAY_CTORS[array]));
            cursor = ctor(
                cursor,
                ELEMENT_ARRAY_OPTIONS,
                ELEMENT_ARRAY_SLOTS,
                ELEMENT_ARRAY_GROWTH,
            );
        }
        // `sub r0, r0, #0xc0` — back off the eight advances.
        let base = cursor.sub((ELEMENT_ARRAY_COUNT - 1) * ELEMENT_ARRAY_STRIDE);
        core::ptr::write_volatile(slot, base);
    }
    core::ptr::read_volatile(slot)
}

/// An array's slot buffer. The table comes from `operator new`, so it
/// is word-aligned and these are plain word loads — the original's
/// `ldr r0, [r0]`.
#[inline(always)]
unsafe fn array_data(base: *const u8) -> *const *mut u8 {
    (base.add(ARRAY_DATA_INDEX * WORD) as *const *const *mut u8).read()
}

/// An array's slot count. Read as a **32-bit signed** word, which is
/// what `ldr r1, [r0, #4]` + `cmp r1, r4` compares on target — the
/// field's width does not grow with the host's pointer width even
/// though its slot does.
#[inline(always)]
unsafe fn array_slots(base: *const u8) -> i32 {
    (base.add(ARRAY_SLOTS_INDEX * WORD) as *const i32).read()
}

/// The body all nine accessors share: build the table, then return slot
/// `index` of array `array`, or NULL when the index is out of range.
#[inline(always)]
unsafe fn element_array_at(array: usize, index: i32) -> *mut u8 {
    let table = element_table();
    let base = table.add(array * ELEMENT_ARRAY_STRIDE);
    if index < 0 || array_slots(base) <= index {
        return core::ptr::null_mut();
    }
    array_data(base).add(index as usize).read()
}

/// element_array0_at — original: `FUN_080f1038` @ 0x080f1038
/// (40 bytes; 47 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's first array (+0x00), or NULL when
/// `index` is negative or at/past the array's slot count.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array0_at(index: i32) -> *mut u8 {
    element_array_at(0, index)
}

/// element_array6_at — original: `FUN_080ed928` @ 0x080ed928
/// (44 bytes; 64 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's seventh array (+0x90). Identical to
/// [`element_array0_at`] but for the array index; the original is the
/// same body plus one redundant `add r0, r0, #0x90`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array6_at(index: i32) -> *mut u8 {
    element_array_at(6, index)
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
    static TABLE_LOCK: Mutex<()> = Mutex::new(());

    /// Backing store the stub allocator hands out — big enough for the
    /// table plus the slot buffers the mock constructor points at.
    /// Word-aligned (a `usize` array), exactly like the block
    /// `operator new` returns.
    static mut ARENA: [usize; 512] = [0; 512];

    /// Sizes passed to `operator new`, in order.
    static mut ALLOC_SIZES: Vec<usize> = Vec::new();

    /// `(this, options, slots, growth)` per constructor call, in order.
    static mut CTOR_CALLS: Vec<(usize, u32, u32, u32)> = Vec::new();

    /// Slot buffers the mock constructor installs, one per array.
    static mut SLOT_BUFFERS: [[*mut u8; 4]; ELEMENT_ARRAY_COUNT] =
        [[ptr::null_mut(); 4]; ELEMENT_ARRAY_COUNT];

    /// How many slots the mock constructor reports per array.
    static mut MOCK_SLOTS: i32 = 4;

    fn alloc_sizes() -> &'static mut Vec<usize> {
        unsafe { &mut *ptr::addr_of_mut!(ALLOC_SIZES) }
    }

    fn ctor_calls() -> &'static mut Vec<(usize, u32, u32, u32)> {
        unsafe { &mut *ptr::addr_of_mut!(CTOR_CALLS) }
    }

    fn arena() -> *mut u8 {
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        alloc_sizes().push(size);
        arena()
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    /// Records the call, then fills the sub-object in with a real slot
    /// buffer so the accessors have something to read.
    unsafe extern "C" fn recording_ctor(
        this: *mut u8,
        options: u32,
        slots: u32,
        growth: u32,
    ) -> *mut u8 {
        let array = (this as usize - arena() as usize) / ELEMENT_ARRAY_STRIDE;
        ctor_calls().push((this as usize - arena() as usize, options, slots, growth));
        let buffer = ptr::addr_of_mut!(SLOT_BUFFERS[array]) as *mut u8;
        (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(buffer);
        let mock_slots = ptr::read_volatile(ptr::addr_of!(MOCK_SLOTS));
        (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut i32).write(mock_slots);
        this
    }

    /// A dummy non-NULL heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached.
    static mut FAKE_HEAP: usize = 0;

    /// Installs the stub allocator plus recording constructors and
    /// clears the cache.
    fn mock() -> MutexGuard<'static, ()> {
        let guard = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            ELEMENT_ARRAY_CTORS = [recording_ctor; ELEMENT_ARRAY_COUNT];
            MOCK_SLOTS = 4;
            alloc_sizes().clear();
            ctor_calls().clear();
            for array in 0..ELEMENT_ARRAY_COUNT {
                for slot in 0..4 {
                    SLOT_BUFFERS[array][slot] = (0x1000 + array * 0x100 + slot * 8) as *mut u8;
                }
            }
            ELEMENT_TABLE = ptr::null_mut();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = crate::heap::veneers::DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            ELEMENT_ARRAY_CTORS = DEFAULT_ELEMENT_ARRAY_CTORS;
            ELEMENT_TABLE = ptr::null_mut();
            alloc_sizes().clear();
            ctor_calls().clear();
        }
        drop(guard);
    }

    fn expected_slot(array: usize, slot: usize) -> *mut u8 {
        (0x1000 + array * 0x100 + slot * 8) as *mut u8
    }

    #[test]
    fn the_table_is_allocated_once_at_its_exact_size() {
        let guard = mock();
        unsafe {
            let first = element_table();
            assert_eq!(first, arena());
            assert_eq!(*alloc_sizes(), std::vec![ELEMENT_TABLE_SIZE]);
            assert_eq!(element_table(), first);
            assert_eq!(element_table(), first);
            assert_eq!(alloc_sizes().len(), 1, "allocated exactly once");
            assert_eq!(ctor_calls().len(), ELEMENT_ARRAY_COUNT, "constructed exactly once");
        }
        restore(guard);
    }

    #[test]
    fn nine_arrays_are_built_at_the_original_offsets_with_the_original_arguments() {
        let guard = mock();
        unsafe {
            element_table();
            let expected: Vec<(usize, u32, u32, u32)> = (0..ELEMENT_ARRAY_COUNT)
                .map(|array| (array * ELEMENT_ARRAY_STRIDE, 0, 10, 2))
                .collect();
            assert_eq!(*ctor_calls(), expected);
        }
        restore(guard);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn the_target_offsets_are_the_original_literals() {
        assert_eq!(ELEMENT_TABLE_SIZE, 0xd8);
        assert_eq!(ELEMENT_ARRAY_STRIDE, 0x18);
        assert_eq!(6 * ELEMENT_ARRAY_STRIDE, 0x90, "array 6 sits at +0x90");
    }

    #[test]
    fn a_pre_seeded_cache_short_circuits_construction() {
        let guard = mock();
        unsafe {
            ELEMENT_TABLE = arena().add(64);
            assert_eq!(element_table(), arena().add(64));
            assert!(alloc_sizes().is_empty());
            assert!(ctor_calls().is_empty());
        }
        restore(guard);
    }

    #[test]
    fn each_accessor_reads_its_own_array() {
        let guard = mock();
        unsafe {
            assert_eq!(element_array0_at(0), expected_slot(0, 0));
            assert_eq!(element_array0_at(3), expected_slot(0, 3));
            assert_eq!(element_array6_at(0), expected_slot(6, 0));
            assert_eq!(element_array6_at(2), expected_slot(6, 2));
        }
        restore(guard);
    }

    #[test]
    fn the_bound_is_exclusive_and_signed() {
        let guard = mock();
        unsafe {
            assert_eq!(element_array6_at(3), expected_slot(6, 3), "the last slot is in range");
            assert!(element_array6_at(4).is_null(), "index == slots is out of range");
            assert!(element_array6_at(5).is_null());
            assert!(element_array6_at(-1).is_null(), "a negative index is out of range");
            assert!(element_array6_at(i32::MIN).is_null());
            assert!(element_array6_at(i32::MAX).is_null());
        }
        restore(guard);
    }

    #[test]
    fn a_slot_count_with_the_sign_bit_set_rejects_every_index() {
        // The original compares `slots` against `index` signed
        // (`cmpge r1, r4` then `ldrgt`), so a count read back with the
        // top bit set is *less* than any non-negative index.
        let guard = mock();
        unsafe {
            MOCK_SLOTS = i32::MIN;
            assert!(element_array6_at(0).is_null());
            assert!(element_array6_at(1).is_null());
        }
        restore(guard);
    }

    #[test]
    fn an_empty_array_yields_null_for_every_index() {
        let guard = mock();
        unsafe {
            MOCK_SLOTS = 0;
            assert!(element_array0_at(0).is_null());
            assert!(element_array6_at(0).is_null());
        }
        restore(guard);
    }

    #[test]
    fn an_out_of_range_index_still_builds_the_table() {
        // The original calls the getter before it tests anything.
        let guard = mock();
        unsafe {
            assert!(element_array6_at(-1).is_null());
            assert_eq!(*alloc_sizes(), std::vec![ELEMENT_TABLE_SIZE]);
            assert!(!ELEMENT_TABLE.is_null());
        }
        restore(guard);
    }

    #[test]
    fn the_cached_base_chains_the_ctor_returns_and_subtracts_eight_strides() {
        // The original advances by 0x18 from each constructor's *return*
        // and ends with `sub r0, r0, #0xc0` on the ninth one, not on the
        // block `operator new` handed out. A constructor that returns
        // `this + 8` therefore shifts the cached base by 9 * 8.
        const NUDGE: usize = 8;
        unsafe extern "C" fn nudging_ctor(
            this: *mut u8,
            _options: u32,
            _slots: u32,
            _growth: u32,
        ) -> *mut u8 {
            this.add(NUDGE)
        }
        let guard = mock();
        unsafe {
            ELEMENT_ARRAY_CTORS = [nudging_ctor; ELEMENT_ARRAY_COUNT];
            assert_eq!(element_table(), arena().add(ELEMENT_ARRAY_COUNT * NUDGE));
        }
        restore(guard);
    }

    #[test]
    fn the_default_ctor_stub_zeroes_one_sub_object_and_returns_it() {
        let guard = TABLE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let block = arena();
            for offset in 0..ELEMENT_ARRAY_STRIDE + 4 {
                block.add(offset).write(0xa5);
            }
            assert_eq!(zeroing_array_ctor(block, 0, 10, 2), block);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                assert_eq!(block.add(offset).read(), 0, "byte +{offset:#x}");
            }
            assert_eq!(block.add(ELEMENT_ARRAY_STRIDE).read(), 0xa5, "no overrun");
            assert!(zeroing_array_ctor(ptr::null_mut(), 0, 10, 2).is_null(), "NULL-safe");
        }
        restore(guard);
    }

    #[test]
    fn the_wired_defaults_leave_every_array_empty() {
        let guard = mock();
        unsafe {
            ELEMENT_ARRAY_CTORS = DEFAULT_ELEMENT_ARRAY_CTORS;
            assert!(element_array0_at(0).is_null());
            assert!(element_array6_at(0).is_null());
            assert!(!ELEMENT_TABLE.is_null(), "the table itself is still built");
        }
        restore(guard);
    }
}
