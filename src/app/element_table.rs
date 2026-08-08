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
//! This module ports the getter and all nine accessors. The two
//! busiest are 0x080ed928 (64 `bl`) and 0x080f1038 (47 `bl`), 111
//! sites across the pair; the other seven (43 `bl` in all) are the
//! same body with a different array index and are one line each.
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
//! - The constructors for arrays 0 through 6 and array 8,
//!   [`element_array0_construct`], [`element_array1_construct`],
//!   [`element_array2_construct`], [`element_array3_construct`],
//!   [`element_array4_construct`], [`element_array5_construct`],
//!   [`element_array6_construct`], and [`element_array8_construct`], are
//!   ported and wired as their defaults. Array 7 remains behind a documented
//!   zeroing stub. The ported arrays are empty, ten-slot containers after
//!   default construction; array 7 still reports zero slots. The
//!   tracker-registration helper each constructor calls is a four-byte
//!   `mov pc, lr` stub in retailOS, so no registration seam is required.
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
/// Word index of the array's live-element count (byte offset 0x08).
const ARRAY_USED_INDEX: usize = 2;

/// Word index of the caller's options word (byte offset 0x0c).
const ARRAY_OPTIONS_INDEX: usize = 3;

/// Word index of the growth step (byte offset 0x10).
const ARRAY_GROWTH_INDEX: usize = 4;

/// Word index of the tracker-label allocation (byte offset 0x14).
const ARRAY_TRACKER_LABEL_INDEX: usize = 5;

/// One of the nine container constructors: takes the sub-object, returns
/// it (the ADS C++ convention the getter's `+0x18` chain relies on).
pub type ElementArrayCtor = unsafe extern "C" fn(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8;

/// Default stub for each still-unported container constructor: zeroes the
/// sub-object and returns it. This intentionally leaves `slots = 0`, so the
/// corresponding accessor reports NULL (see the module header).
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

/// Host-test source for the dynamic `fTable` name. On hardware, the original
/// loads the source pointer from `DAT_083d3f2c + 4` (0x0897baac + 4).
#[cfg(not(target_os = "none"))]
static HOST_ARRAY0_TRACKER_NAME_EMPTY: [u8; 1] = [0];

#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY0_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();

/// Host-test source for the second constructor's distinct runtime fTable
/// record. It has the same empty fallback but must remain independently
/// swappable: retailOS loads it from 0x0897bbc4 + 4, not array 0's record.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY1_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();

/// Host-test source for the third constructor's independent runtime fTable
/// record. It must not alias either earlier constructor: retailOS loads
/// 0x0897bab8 + 4 for this array.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY2_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();

/// Host-test source for the fourth constructor's independent runtime fTable
/// record. It must not alias the first three: retailOS loads it from
/// 0x0897b904 + 4 for this array.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY3_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();

/// Host-test source for the fifth constructor's independent runtime fTable
/// record. It must not alias the first four: retailOS loads 0x0897cc8c + 4
/// for this array.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY4_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();

/// Host-test source for the sixth constructor's independent runtime fTable
/// record. RetailOS loads its name from 0x0897cbec + 4.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY5_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
/// Host-test source for the seventh constructor's independent runtime fTable
/// record. RetailOS loads its name from 0x0897cba0 + 4.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY6_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
///
/// Host-test source for the ninth constructor's independent runtime fTable
/// record. RetailOS loads its name from 0x0897bc00 + 4.
#[cfg(not(target_os = "none"))]
static mut HOST_ARRAY8_TRACKER_NAME: *const u8 = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();

/// Returns the fTable name whose shortened copy is retained for the inert
/// tracker record. `FUN_082a7774` is exactly `ldr r0, [r0, #4]; bx lr`.
#[inline(always)]
unsafe fn array0_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        // The firmware completes this runtime-data record before this
        // constructor can be called; preserve its direct +4 load.
        return (0x0897_baac as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY0_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the second array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array1_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_bbc4 as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY1_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the third array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array2_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_bab8 as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY2_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the fourth array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array3_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_b904 as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY3_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the fifth array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array4_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_cc8c as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY4_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the sixth array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array5_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_cbec as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY5_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the seventh array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array6_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_cba0 as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY6_TRACKER_NAME))
    }
}

/// Returns the fTable name associated with the ninth array's independent
/// runtime-data record. `FUN_082a7774` loads the record's word at +4.
#[inline(always)]
unsafe fn array8_tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    {
        return (0x0897_bc00 as *const *const u8).add(1).read();
    }

    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ARRAY8_TRACKER_NAME))
    }
}

/// Counts a NUL-terminated tracker name, matching `FUN_08392478`.
#[inline(always)]
unsafe fn tracker_name_len(name: *const u8) -> usize {
    let mut len = 0;
    while name.add(len).read_volatile() != 0 {
        len += 1;
    }
    len
}

/// Copies exactly `len` bytes like `strncpy`: after the first NUL, remaining
/// destination bytes are zero-padded. Volatile byte operations keep ARM LLVM
/// from replacing this loop with an unavailable libc call.
#[inline(always)]
unsafe fn copy_tracker_name(dst: *mut u8, src: *const u8, len: usize) {
    let mut saw_nul = false;
    for index in 0..len {
        let byte = if saw_nul {
            0
        } else {
            let byte = src.add(index).read_volatile();
            saw_nul = byte == 0;
            byte
        };
        dst.add(index).write_volatile(byte);
    }
}

/// element_array0_construct — original: `FUN_083d3e8c` @ 0x083d3e8c
/// (160 bytes).
///
/// Constructs the first 0x18-byte element-array container. It stores its
/// capacity, empty live count, options, and growth word; allocates and
/// zeroes `slots` pointer-width slot bytes; then allocates a shortened copy
/// of the runtime fTable name at +0x14 for the `Tracker<%s> fTable=%x,
/// fSize=%d` instrumentation call. The final tracker helper
/// (`FUN_083d3cec`) is a four-byte no-op, and the constructor returns
/// `this` unconditionally. There is no allocation-failure branch: allocation
/// results are stored and passed onward exactly as returned.
///
/// On target the fTable name is read from the retailOS runtime-data word
/// 0x0897baac + 4. The host-only source is swappable by tests because that
/// firmware address is not mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array0_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    // `mov r0, r2, lsl #2` on ARM. WORD is four on target and scales only
    // the host fixture's pointer slots to keep its layout sound.
    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array0_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    // The two strlen calls after the allocation feed r6 and the `<= 10`
    // predicate separately in ARM; their common pure result is name_len.
    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array1_construct — original: `FUN_083d4354` @ 0x083d4354
/// (160 bytes).
///
/// Constructs the second 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, and allocates a shortened copy of
/// the fTable name from its own runtime record for inert
/// `Tracker<%s> fTable=%x, fSize=%d` instrumentation. `FUN_083d41b4` is a
/// four-byte no-op, so it has no port seam. The constructor contains no
/// allocation-failure branch: it stores and uses allocation results exactly
/// as returned, then returns `this`.
///
/// On target the fTable name comes from 0x0897bbc4 + 4. The host-only source
/// is independently swappable in tests because firmware runtime data is not
/// mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array1_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array1_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array2_construct — original: `FUN_083d40f0` @ 0x083d40f0
/// (160 bytes).
///
/// Constructs the third 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, and allocates a shortened copy of
/// the fTable name from its own runtime record for inert
/// `Tracker<%s> fTable=%x, fSize=%d` instrumentation. `FUN_083d3f50` is a
/// four-byte no-op, so it has no port seam. The constructor contains no
/// allocation-failure branch: it stores and uses allocation results exactly
/// as returned, then returns `this`.
///
/// On target the fTable name comes from 0x0897bab8 + 4. The host-only source
/// is independently swappable in tests because firmware runtime data is not
/// mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array2_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array2_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array3_construct — original: `FUN_083d3c28` @ 0x083d3c28
/// (160 bytes).
///
/// Constructs the fourth 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, and allocates a shortened copy of
/// the fTable name from its own runtime record for inert
/// `Tracker<%s> fTable=%x, fSize=%d` instrumentation. `FUN_083d3a8c` is a
/// four-byte no-op, so it has no port seam. The constructor contains no
/// allocation-failure branch: it stores and uses allocation results exactly
/// as returned, then returns `this`.
///
/// On target the fTable name comes from 0x0897b904 + 4. The host-only source
/// is independently swappable in tests because firmware runtime data is not
/// mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array3_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array3_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array4_construct — original: `FUN_083d56b8` @ 0x083d56b8
/// (160 bytes).
///
/// Constructs the fifth 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, and allocates a shortened copy of
/// the fTable name from its own runtime record for inert
/// `Tracker<%s> fTable=%x, fSize=%d` instrumentation. `FUN_083d551c` is a
/// four-byte no-op, so it has no port seam. The constructor contains no
/// allocation-failure branch: it stores and uses allocation results exactly
/// as returned, then returns `this`.
///
/// On target the fTable name comes from 0x0897cc8c + 4. The host-only source
/// is independently swappable in tests because firmware runtime data is not
/// mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array4_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array4_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array5_construct — original: `FUN_083d51dc` @ 0x083d51dc
/// (160 bytes).
///
/// Constructs the sixth 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, and allocates a shortened copy of
/// the fTable name from its own runtime record for inert
/// `Tracker<%s> fTable=%x, fSize=%d` instrumentation. `FUN_083d503c` is a
/// four-byte `bx lr`, so it has no port seam. The constructor contains no
/// allocation-failure branch: it stores and uses allocation results exactly
/// as returned, then returns `this`.
///
/// On target the fTable name comes from 0x0897cbec + 4. The host-only source
/// is independently swappable in tests because firmware runtime data is not
/// mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array5_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array5_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array6_construct — original: `FUN_083d4a94` @ 0x083d4a94
/// (160 bytes).
///
/// Constructs the seventh 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, and allocates a shortened copy of
/// the fTable name from its independent runtime record for inert
/// `Tracker<%s> fTable=%x, fSize=%d` instrumentation. `FUN_083d48f8` is a
/// four-byte `bx lr`, so it has no port seam. The constructor contains no
/// allocation-failure branch: it stores and uses allocation results exactly
/// as returned, then returns `this`.
///
/// On target the fTable name comes from 0x0897cba0 + 4. The host-only source
/// is independently swappable in tests because firmware runtime data is not
/// mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array6_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array6_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// element_array8_construct — original: `FUN_083d45b4` @ 0x083d45b4
/// (160 bytes).
///
/// Constructs the ninth 0x18-byte element-array container. It initializes
/// `{data, slots, used, options, growth, tracker_label}` at offsets
/// `{+0x00, +0x04, +0x08, +0x0c, +0x10, +0x14}`, allocates and zeroes
/// `slots * 4` bytes for its data buffer, then allocates a shortened copy of
/// the fTable name for the inert `Tracker<%s> fTable=%x, fSize=%d`
/// instrumentation. `FUN_083d4418` is a four-byte `bx lr`, so it has no port
/// seam. There is no allocation-failure branch: allocation results are stored
/// and used exactly as returned, then the constructor returns `this`.
///
/// On target the fTable name is read from runtime-data record 0x0897bc00 + 4.
/// The host-only source is independently swappable in tests because that
/// firmware address is not mapped there.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array8_construct(
    this: *mut u8,
    options: u32,
    slots: u32,
    growth: u32,
) -> *mut u8 {
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());
    (this.add(ARRAY_SLOTS_INDEX * WORD) as *mut u32).write(slots);
    (this.add(ARRAY_USED_INDEX * WORD) as *mut u32).write(0);
    (this.add(ARRAY_OPTIONS_INDEX * WORD) as *mut u32).write(options);
    (this.add(ARRAY_GROWTH_INDEX * WORD) as *mut u32).write(growth);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(core::ptr::null_mut());

    let slot_bytes = (slots as usize).wrapping_mul(WORD);
    let data = operator_new(slot_bytes);
    (this.add(ARRAY_DATA_INDEX * WORD) as *mut *mut u8).write(data);
    for offset in 0..slot_bytes {
        data.add(offset).write_volatile(0);
    }

    let name = array8_tracker_name();
    let name_len = tracker_name_len(name);
    let label = operator_new(name_len);
    (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *mut *mut u8).write(label);

    let source_offset = if name_len <= 10 { 1 } else { 2 };
    copy_tracker_name(label, name.add(source_offset), name_len);
    this
}

/// Indirect dispatch table for the nine container constructors, in the order
/// the getter calls them (array 0 first).
pub type ElementArrayCtors = [ElementArrayCtor; ELEMENT_ARRAY_COUNT];

/// Wired defaults: arrays 0 through 6 and 8 use their retailOS constructors;
/// array 7 remains a documented zeroing stub until its own port lands.

pub(crate) const DEFAULT_ELEMENT_ARRAY_CTORS: ElementArrayCtors = [
    element_array0_construct,
    element_array1_construct,
    element_array2_construct,
    element_array3_construct,
    element_array4_construct,
    element_array5_construct,
    element_array6_construct,
    zeroing_array_ctor,
    element_array8_construct,
];

/// The active constructors. Host tests install recording mocks; the real
/// ports replace the defaults when they exist.
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

/// element_array1_at — original: `FUN_080f0fb4` @ 0x080f0fb4
/// (44 bytes; 2 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's second array (+0x18), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array1_at(index: i32) -> *mut u8 {
    element_array_at(1, index)
}

/// element_array2_at — original: `FUN_080f108c` @ 0x080f108c
/// (44 bytes; 7 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's third array (+0x30), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array2_at(index: i32) -> *mut u8 {
    element_array_at(2, index)
}

/// element_array3_at — original: `FUN_080f1060` @ 0x080f1060
/// (44 bytes; 5 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's fourth array (+0x48), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array3_at(index: i32) -> *mut u8 {
    element_array_at(3, index)
}

/// element_array4_at — original: `FUN_080f100c` @ 0x080f100c
/// (44 bytes; 6 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's fifth array (+0x60), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array4_at(index: i32) -> *mut u8 {
    element_array_at(4, index)
}

/// element_array5_at — original: `FUN_080ed8fc` @ 0x080ed8fc
/// (44 bytes; 9 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's sixth array (+0x78), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array5_at(index: i32) -> *mut u8 {
    element_array_at(5, index)
}

/// element_array7_at — original: `FUN_080ed8d0` @ 0x080ed8d0
/// (44 bytes; 8 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's eighth array (+0xa8), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array7_at(index: i32) -> *mut u8 {
    element_array_at(7, index)
}

/// element_array8_at — original: `FUN_080f0fe0` @ 0x080f0fe0
/// (44 bytes; 6 `bl` call sites, binary-scanned).
///
/// Slot `index` of the table's ninth array (+0xc0), or NULL when
/// `index` is negative or at/past the array's slot count. Same body as
/// [`element_array0_at`] with a different array offset.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn element_array8_at(index: i32) -> *mut u8 {
    element_array_at(8, index)
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

    /// Per-call override results for the allocator. An unset entry preserves
    /// the ordinary table fixture's `arena()` result.
    static mut ALLOC_RESULTS: [*mut u8; 19] = [ptr::null_mut(); 19];

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
        let index = alloc_sizes().len();
        alloc_sizes().push(size);
        let result = (*ptr::addr_of!(ALLOC_RESULTS))[index];
        if result.is_null() {
            arena()
        } else {
            result
        }

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
            ALLOC_RESULTS = [ptr::null_mut(); 19];
            HOST_ARRAY0_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY1_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY2_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY3_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY4_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY5_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY6_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY8_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
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
            ALLOC_RESULTS = [ptr::null_mut(); 19];
            HOST_ARRAY0_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY1_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY2_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY3_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY4_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY5_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY6_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
            HOST_ARRAY8_TRACKER_NAME = HOST_ARRAY0_TRACKER_NAME_EMPTY.as_ptr();
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
            let accessors: [unsafe extern "C" fn(i32) -> *mut u8; ELEMENT_ARRAY_COUNT] = [
                element_array0_at,
                element_array1_at,
                element_array2_at,
                element_array3_at,
                element_array4_at,
                element_array5_at,
                element_array6_at,
                element_array7_at,
                element_array8_at,
            ];
            for (array, accessor) in accessors.iter().enumerate() {
                assert_eq!(accessor(0), expected_slot(array, 0), "array {array} slot 0");
                assert_eq!(accessor(3), expected_slot(array, 3), "array {array} slot 3");
                assert!(accessor(4).is_null(), "array {array} slot == bound");
                assert!(accessor(-1).is_null(), "array {array} negative index");
            }
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
    fn array0_constructor_lays_out_and_zeroes_its_two_allocations() {
        let guard = mock();
        let tracker_name = *b"TrackerArray0\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(3 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY0_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(
                element_array0_construct(this, 0x1122_3344, 3, 0x5566_7788),
                this,
                "the constructor returns its this pointer"
            );
            assert_eq!(*alloc_sizes(), std::vec![3 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 3);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(
                core::slice::from_raw_parts(slot_data, 3 * WORD),
                &[0u8; 3 * WORD],
                "the complete slot allocation is zeroed"
            );

            assert_eq!(slot_data.add(3 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray0\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
        }
        restore(guard);
    }

    #[test]
    fn array1_constructor_lays_out_its_independent_tracker_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"fTable\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(2 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY1_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(
                element_array1_construct(this, 0x1122_3344, 2, 0x5566_7788),
                this,
                "the constructor returns its this pointer"
            );
            assert_eq!(*alloc_sizes(), std::vec![2 * WORD, 6]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 2);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(
                core::slice::from_raw_parts(slot_data, 2 * WORD),
                &[0u8; 2 * WORD],
                "the complete slot allocation is zeroed"
            );
            assert_eq!(slot_data.add(2 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 6),
                b"Table\0",
                "the short fTable name skips one byte"
            );
        }
        restore(guard);
    }

    #[test]
    fn array2_constructor_initializes_its_own_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"TrackerArray2\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(4 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY2_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(element_array2_construct(this, 0x1122_3344, 4, 0x5566_7788), this);
            assert_eq!(*alloc_sizes(), std::vec![4 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 4);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(core::slice::from_raw_parts(slot_data, 4 * WORD), &[0u8; 4 * WORD]);
            assert_eq!(slot_data.add(4 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray2\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
        }
        restore(guard);
    }

    #[test]
    fn array3_constructor_lays_out_its_independent_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"TrackerArray3\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(5 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY3_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(element_array3_construct(this, 0x1122_3344, 5, 0x5566_7788), this);
            assert_eq!(*alloc_sizes(), std::vec![5 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 5);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(core::slice::from_raw_parts(slot_data, 5 * WORD), &[0u8; 5 * WORD]);
            assert_eq!(slot_data.add(5 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray3\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
        }
        restore(guard);
    }

    #[test]
    fn array4_constructor_lays_out_its_independent_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"TrackerArray4\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(6 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY4_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(element_array4_construct(this, 0x1122_3344, 6, 0x5566_7788), this);
            assert_eq!(*alloc_sizes(), std::vec![6 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 6);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(core::slice::from_raw_parts(slot_data, 6 * WORD), &[0u8; 6 * WORD]);
            assert_eq!(slot_data.add(6 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray4\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
        }
        restore(guard);
    }

    #[test]
    fn array5_constructor_lays_out_its_own_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"TrackerArray5\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(7 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY5_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(element_array5_construct(this, 0x1122_3344, 7, 0x5566_7788), this);
            assert_eq!(*alloc_sizes(), std::vec![7 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 7);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(core::slice::from_raw_parts(slot_data, 7 * WORD), &[0u8; 7 * WORD]);
            assert_eq!(slot_data.add(7 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray5\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
        }
        restore(guard);
    }

    #[test]
    fn array6_constructor_lays_out_its_own_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"TrackerArray6\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(8 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY6_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(element_array6_construct(this, 0x1122_3344, 8, 0x5566_7788), this);
            assert_eq!(*alloc_sizes(), std::vec![8 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 8);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(core::slice::from_raw_parts(slot_data, 8 * WORD), &[0u8; 8 * WORD]);
            assert_eq!(slot_data.add(8 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray6\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
        }
        restore(guard);
    }

    #[test]
    fn array8_constructor_lays_out_its_independent_record_and_returns_this() {
        let guard = mock();
        let tracker_name = *b"TrackerArray8\0";
        unsafe {
            let this = arena().add(0x100);
            let slot_data = arena().add(0x200);
            let tracker_label = arena().add(0x300);
            for offset in 0..ELEMENT_ARRAY_STRIDE {
                this.add(offset).write(0xa5);
            }
            for offset in 0..(9 * WORD + 1) {
                slot_data.add(offset).write(0xa5);
            }
            for offset in 0..tracker_name.len() {
                tracker_label.add(offset).write(0xa5);
            }
            HOST_ARRAY8_TRACKER_NAME = tracker_name.as_ptr();
            ALLOC_RESULTS[0] = slot_data;
            ALLOC_RESULTS[1] = tracker_label;

            assert_eq!(element_array8_construct(this, 0x1122_3344, 9, 0x5566_7788), this);
            assert_eq!(*alloc_sizes(), std::vec![9 * WORD, 13]);
            assert_eq!(
                (this.add(ARRAY_DATA_INDEX * WORD) as *const *mut u8).read(),
                slot_data
            );
            assert_eq!((this.add(ARRAY_SLOTS_INDEX * WORD) as *const u32).read(), 9);
            assert_eq!((this.add(ARRAY_USED_INDEX * WORD) as *const u32).read(), 0);
            assert_eq!(
                (this.add(ARRAY_OPTIONS_INDEX * WORD) as *const u32).read(),
                0x1122_3344
            );
            assert_eq!(
                (this.add(ARRAY_GROWTH_INDEX * WORD) as *const u32).read(),
                0x5566_7788
            );
            assert_eq!(
                (this.add(ARRAY_TRACKER_LABEL_INDEX * WORD) as *const *mut u8).read(),
                tracker_label
            );
            assert_eq!(core::slice::from_raw_parts(slot_data, 9 * WORD), &[0u8; 9 * WORD]);
            assert_eq!(slot_data.add(9 * WORD).read(), 0xa5, "slot zeroing stops at capacity");
            assert_eq!(
                core::slice::from_raw_parts(tracker_label, 13),
                b"ackerArray8\0\0",
                "the long fTable name skips two bytes and strncpy-pads"
            );
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
    fn wired_defaults_construct_all_but_array7_and_leave_all_slots_empty() {
        let guard = mock();
        unsafe {
            // The table block is allocation 0; each ported array allocates
            // data plus a tracker label, so none may alias it.
            ALLOC_RESULTS[1] = arena().add(0x200);
            ALLOC_RESULTS[2] = arena().add(0x300);
            ALLOC_RESULTS[3] = arena().add(0x400);
            ALLOC_RESULTS[4] = arena().add(0x500);
            ALLOC_RESULTS[5] = arena().add(0x600);
            ALLOC_RESULTS[6] = arena().add(0x700);
            ALLOC_RESULTS[7] = arena().add(0x800);
            ALLOC_RESULTS[8] = arena().add(0x900);
            ALLOC_RESULTS[9] = arena().add(0xa00);
            ALLOC_RESULTS[10] = arena().add(0xb00);
            ALLOC_RESULTS[11] = arena().add(0xc00);
            ALLOC_RESULTS[12] = arena().add(0xd00);
            ALLOC_RESULTS[13] = arena().add(0xe00);
            ALLOC_RESULTS[14] = arena().add(0xf00);
            ALLOC_RESULTS[15] = arena().add(0x1000);
            ALLOC_RESULTS[16] = arena().add(0x1100);
            ELEMENT_ARRAY_CTORS = DEFAULT_ELEMENT_ARRAY_CTORS;
            assert!(element_array0_at(0).is_null());
            assert_eq!(array_slots(ELEMENT_TABLE), 10, "array 0 has its retail capacity");
            assert!(element_array1_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(ELEMENT_ARRAY_STRIDE)),
                10,
                "array 1 has its retail capacity"
            );
            assert!(element_array2_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(2 * ELEMENT_ARRAY_STRIDE)),
                10,
                "array 2 has its retail capacity"
            );
            assert!(element_array3_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(3 * ELEMENT_ARRAY_STRIDE)),
                10,
                "array 3 has its retail capacity"
            );
            assert!(element_array4_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(4 * ELEMENT_ARRAY_STRIDE)),
                10,
                "array 4 has its retail capacity"
            );
            assert!(element_array5_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(5 * ELEMENT_ARRAY_STRIDE)),
                10,
                "array 5 has its retail capacity"
            );
            assert!(element_array6_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(6 * ELEMENT_ARRAY_STRIDE)),
                10,
                "array 6 has its retail capacity"
            );
            assert!(element_array7_at(0).is_null(), "array 7 remains unported");
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(7 * ELEMENT_ARRAY_STRIDE)),
                0,
                "the array-7 stub retains no slots"
            );
            assert!(element_array8_at(0).is_null());
            assert_eq!(
                array_slots(ELEMENT_TABLE.add(8 * ELEMENT_ARRAY_STRIDE)),
                10,
                "array 8 has its retail capacity"
            );
        }
        restore(guard);
    }
}
