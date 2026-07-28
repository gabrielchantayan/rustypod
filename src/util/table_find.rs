//! Two table lookups from unrelated subsystems, both "scan a table of
//! fixed-size records for the one that matches":
//!
//! - [`table6_find_by_key`] — a six-slot request registry keyed by an
//!   object handle (`FUN_081c93fc` @ 0x081c93fc).
//! - [`registry_find_for_slot`] — the 275-entry id registry with a
//!   per-slot availability mask (`FUN_08138bd0` @ 0x08138bd0).
//!
//! # table6_find_by_key
//!
//! `table6_find_by_key` — original: `FUN_081c93fc` @ 0x081c93fc
//! (52 bytes; 3 `bl` call sites, binary-scanned).
//!
//! A fixed six-slot registry of in-flight requests, keyed by an object
//! handle. The caller passes a *handle*: a pointer whose first word is
//! the table base (on device the table lives at `owner + 0x28 + 0x3c`
//! and every access is taken under the lock at `owner + 0x28 + 0x40` —
//! `FUN_08094404` / `FUN_0809449c`). Each slot is 8 bytes: the key at
//! +0 and a state byte at +4 that the two callers drive through
//! 0 (idle) -> 1 (running) -> 2 (done); the accessor @ 0x0829dd30 reads
//! the same byte back, returning 0 when the key is not registered.
//!
//! The scan is unconditional over all six slots — there is no
//! "occupied" flag, so a `key` of 0 matches the first zeroed slot,
//! exactly as on device. Returns the slot pointer, or NULL when no slot
//! holds the key.
//!
//! Slot fields are typed struct members, so the 8-byte target stride is
//! reproduced on a 64-bit host too (asserted below); the table base is
//! read through the handle by word index, never a literal byte offset.
//!
//! Codegen deviation: the original keeps a real six-iteration loop
//! (13 instructions); LLVM fully unrolls the constant trip count into
//! 29 straight-line instructions. Behaviorally identical — the slot
//! order and the early return on the first match are preserved.
//!
//! # registry_find_for_slot
//!
//! `registry_find_for_slot` — original: `FUN_08138bd0` @ 0x08138bd0
//! (88 bytes; 8 `bl` call sites, binary-scanned).
//!
//! Linear scan of a 275-entry table of 12-byte records for the one
//! whose id matches *and* which is available on the caller's slot:
//!
//! ```text
//! record +0x0  pointer to the full descriptor (0x08138e94 reads a u16
//!              at descriptor +0x3c through it)
//! record +0x4  u16 id           — compared against the `id` argument
//! record +0x6  u8  slot mask    — bit (1 << slot) must be set
//! record +0x8  handle           — fed to the decoder @ 0x082cdc94 by
//!                                 the caller @ 0x08138650
//! ```
//!
//! Both the base (0x089ccc38) and the count (275, an immediate in the
//! literal pool at 0x08138c2c — not a global, despite Ghidra's
//! `DAT_08138c2c`) are baked into the code, so the table is a static
//! array filled in by the ADS runtime initializers.
//!
//! `slot` is a small index: every caller asserts it is <= 2 before
//! calling (`FUN_0813858c`, `FUN_08193e84`), and each slot owns a
//! 0x114-byte state record in the array @ 0x08ad0f34 whose +4 field is
//! set to this function's result — the slot's "current descriptor".
//! `id` 0 is the default descriptor.
//!
//! Faithful details:
//! - The first argument is a `this` pointer the original never reads
//!   (`mov r0, #0` overwrites it before the loop). Kept in the
//!   signature because all 8 call sites pass it.
//! - The mask is built with an ARM *register* shift and then truncated
//!   to a byte: `1 << (slot & 0xff)`, zero for `slot` 32..=255, then
//!   `& 0xff`. So slots >= 8 can never match. `berec::arm_lsl` supplies
//!   those semantics (Rust's `<<` would panic/mask instead).
//! - The id compare is `ldrh` (zero-extended) against the full 32-bit
//!   argument, so an `id` above 0xffff never matches.
//! - The loop is a do-while: the record at index 0 is examined before
//!   the count is ever tested. With the count baked at 275 that is not
//!   observable on device, but the port keeps the shape.
//!
//! Deviation (block_mgr.rs precedent): the table is the crate static
//! [`SLOT_RECORDS`] rather than living at 0x089ccc38 — that RW page is
//! runtime-initialized (the decrypted image holds UI view-name strings
//! there). It defaults to all-zero, so lookups miss (mask 0) until
//! something fills it in.

/// Number of slots the original scans (`mov r3, #6`).
pub const TABLE_SLOTS: usize = 6;

/// One 8-byte registry slot.
#[repr(C)]
pub struct RequestSlot {
    /// +0x0: the object handle this slot is registered for.
    pub key: u32,
    /// +0x4: request state — 0 idle, 1 running, 2 done.
    pub state: u8,
    /// +0x5..+0x7: not touched by this cluster.
    pub reserved: [u8; 3],
}

// Target-exact layout (the stride the original's `lsl #3` assumes).
const _: [u8; 0x04] = [0; core::mem::offset_of!(RequestSlot, state)];
const _: [u8; 0x08] = [0; core::mem::size_of::<RequestSlot>()];

/// table6_find_by_key — original: `FUN_081c93fc` @ 0x081c93fc
/// (52 bytes).
///
/// Returns the slot whose key equals `key`, scanning all six slots in
/// order; NULL when none matches.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn table6_find_by_key(
    table: *const *mut RequestSlot,
    key: u32,
) -> *mut RequestSlot {
    let base = table.read();
    let mut index = 0usize;
    while index < TABLE_SLOTS {
        let slot = base.add(index);
        if (*slot).key == key {
            return slot;
        }
        index += 1;
    }
    core::ptr::null_mut()
}

/// One 12-byte id-registry record (see the module header).
#[repr(C)]
pub struct SlotRecord {
    /// +0x0: the full descriptor this record points at.
    pub descriptor: *mut u8,
    /// +0x4: the id callers look up.
    pub id: u16,
    /// +0x6: bit `1 << slot` set for every slot that can use it.
    pub slot_mask: u8,
    /// +0x7: not read by this cluster.
    pub reserved7: u8,
    /// +0x8: opaque handle consumed by the caller @ 0x08138650.
    pub handle: *mut u8,
}

// Target-exact layout (the 12-byte stride the original's `i * 0xc`
// assumes). On a 64-bit host the record is wider but the fields stay
// disjoint, and the scan strides by `size_of` either way.
#[cfg(target_pointer_width = "32")]
mod slot_record_layout {
    use super::SlotRecord;
    const _: [u8; 0x04] = [0; core::mem::offset_of!(SlotRecord, id)];
    const _: [u8; 0x06] = [0; core::mem::offset_of!(SlotRecord, slot_mask)];
    const _: [u8; 0x08] = [0; core::mem::offset_of!(SlotRecord, handle)];
    const _: [u8; 0x0c] = [0; core::mem::size_of::<SlotRecord>()];
}

/// Record count baked into the original's literal pool (0x113).
pub const SLOT_RECORD_COUNT: usize = 275;

/// An unfilled record — the state the whole table starts in.
const EMPTY_SLOT_RECORD: SlotRecord = SlotRecord {
    descriptor: core::ptr::null_mut(),
    id: 0,
    slot_mask: 0,
    reserved7: 0,
    handle: core::ptr::null_mut(),
};

/// The registry table (original: the fixed base 0x089ccc38 — see the
/// module-header deviation).
pub static mut SLOT_RECORDS: [SlotRecord; SLOT_RECORD_COUNT] =
    [EMPTY_SLOT_RECORD; SLOT_RECORD_COUNT];

/// registry_find_for_slot — original: `FUN_08138bd0` @ 0x08138bd0
/// (88 bytes).
///
/// Returns the first record whose `id` matches and whose `slot_mask`
/// has bit `1 << slot` set; NULL when the table holds no such record.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn registry_find_for_slot(
    _this: *mut u8,
    slot: u32,
    id: u32,
) -> *mut SlotRecord {
    let wanted_bit = crate::util::berec::arm_lsl(1, slot) & 0xff;
    let base = core::ptr::addr_of_mut!(SLOT_RECORDS) as *mut SlotRecord;

    let mut index = 0usize;
    loop {
        let record = base.add(index);
        if (*record).id as u32 == id && (*record).slot_mask as u32 & wanted_bit != 0 {
            return record;
        }
        index += 1;
        if index >= SLOT_RECORD_COUNT {
            return core::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::ptr;
    use std::sync::{Mutex, MutexGuard};

    fn slot(key: u32, state: u8) -> RequestSlot {
        RequestSlot { key, state, reserved: [0; 3] }
    }

    fn table(slots: &mut [RequestSlot; TABLE_SLOTS]) -> *mut RequestSlot {
        slots.as_mut_ptr()
    }

    fn find(base: *mut RequestSlot, key: u32) -> *mut RequestSlot {
        let handle = base;
        unsafe { table6_find_by_key(&handle as *const *mut RequestSlot, key) }
    }

    #[test]
    fn finds_the_slot_at_every_index() {
        let mut slots =
            [slot(10, 0), slot(20, 1), slot(30, 2), slot(40, 0), slot(50, 1), slot(60, 2)];
        let base = table(&mut slots);
        for i in 0..TABLE_SLOTS {
            let key = ((i as u32) + 1) * 10;
            assert_eq!(find(base, key), unsafe { base.add(i) }, "slot {i}");
        }
    }

    #[test]
    fn returns_the_first_match_when_a_key_is_duplicated() {
        let mut slots =
            [slot(1, 0), slot(7, 1), slot(3, 0), slot(7, 2), slot(5, 0), slot(6, 0)];
        let base = table(&mut slots);
        assert_eq!(find(base, 7), unsafe { base.add(1) });
    }

    #[test]
    fn a_full_table_with_no_match_returns_null() {
        let mut slots =
            [slot(1, 0), slot(2, 0), slot(3, 0), slot(4, 0), slot(5, 0), slot(6, 0)];
        let base = table(&mut slots);
        assert_eq!(find(base, 7), ptr::null_mut());
    }

    #[test]
    fn key_zero_matches_the_first_zeroed_slot() {
        // No "occupied" flag exists: the original compares raw keys, so
        // a zero key finds free slots. Callers rely on this.
        let mut slots =
            [slot(9, 2), slot(0, 0), slot(0, 0), slot(0, 0), slot(0, 0), slot(0, 0)];
        let base = table(&mut slots);
        assert_eq!(find(base, 0), unsafe { base.add(1) });
    }

    #[test]
    fn the_scan_stops_after_six_slots() {
        // A seventh entry holding the key must never be reached.
        let mut slots: [RequestSlot; 7] = [
            slot(1, 0),
            slot(2, 0),
            slot(3, 0),
            slot(4, 0),
            slot(5, 0),
            slot(6, 0),
            slot(0xabcd, 0),
        ];
        let base = slots.as_mut_ptr();
        assert_eq!(find(base, 0xabcd), ptr::null_mut());
    }

    #[test]
    fn the_state_byte_is_reachable_through_the_returned_slot() {
        let mut slots =
            [slot(1, 0), slot(2, 0), slot(0x1234, 0), slot(4, 0), slot(5, 0), slot(6, 0)];
        let base = table(&mut slots);
        let found = find(base, 0x1234);
        assert!(!found.is_null());
        unsafe { (*found).state = 2 };
        assert_eq!(slots[2].state, 2);
    }

    /// Serializes the tests that fill the global registry table.
    static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

    /// Installs `entries` (index, id, mask) into the global table and
    /// hands back the guard; the caller passes it to [`clear_registry`].
    fn with_registry(entries: &[(usize, u16, u8)]) -> MutexGuard<'static, ()> {
        let guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let base = ptr::addr_of_mut!(SLOT_RECORDS) as *mut SlotRecord;
            for &(index, id, mask) in entries {
                (*base.add(index)).id = id;
                (*base.add(index)).slot_mask = mask;
            }
        }
        guard
    }

    /// Zeroes the table again. Takes the guard by value so it cannot be
    /// re-locked while still held (the seek_core.rs rule).
    fn clear_registry(guard: MutexGuard<'static, ()>) {
        unsafe {
            let base = ptr::addr_of_mut!(SLOT_RECORDS) as *mut SlotRecord;
            for index in 0..SLOT_RECORD_COUNT {
                (*base.add(index)).id = 0;
                (*base.add(index)).slot_mask = 0;
            }
        }
        drop(guard);
    }

    fn find_for_slot(slot: u32, id: u32) -> *mut SlotRecord {
        unsafe { registry_find_for_slot(ptr::null_mut(), slot, id) }
    }

    fn record(index: usize) -> *mut SlotRecord {
        unsafe { (ptr::addr_of_mut!(SLOT_RECORDS) as *mut SlotRecord).add(index) }
    }

    #[test]
    fn finds_the_record_whose_id_and_slot_bit_both_match() {
        let guard = with_registry(&[(3, 0x200, 0b0000_0101)]);
        assert_eq!(find_for_slot(0, 0x200), record(3));
        assert_eq!(find_for_slot(2, 0x200), record(3));
        assert_eq!(find_for_slot(1, 0x200), ptr::null_mut(), "slot 1 is not in the mask");
        clear_registry(guard);
    }

    #[test]
    fn an_id_with_no_record_misses() {
        let guard = with_registry(&[(0, 0x200, 0xff)]);
        assert_eq!(find_for_slot(0, 0x201), ptr::null_mut());
        clear_registry(guard);
    }

    #[test]
    fn the_empty_table_misses_because_every_mask_is_zero() {
        let guard = with_registry(&[]);
        // id 0 matches every zeroed record, but mask 0 rejects them all.
        assert_eq!(find_for_slot(0, 0), ptr::null_mut());
        clear_registry(guard);
    }

    #[test]
    fn id_zero_is_the_default_record() {
        let guard = with_registry(&[(7, 0, 0b0000_0111)]);
        assert_eq!(find_for_slot(1, 0), record(7), "the first id-0 record with the slot bit");
        clear_registry(guard);
    }

    #[test]
    fn the_first_matching_record_wins() {
        let guard = with_registry(&[(9, 0x300, 0b0000_0010), (40, 0x300, 0b0000_0010)]);
        assert_eq!(find_for_slot(1, 0x300), record(9));
        clear_registry(guard);
    }

    #[test]
    fn the_last_record_is_reachable_and_nothing_past_it_is() {
        let guard = with_registry(&[(SLOT_RECORD_COUNT - 1, 0x400, 0b0000_0001)]);
        assert_eq!(find_for_slot(0, 0x400), record(SLOT_RECORD_COUNT - 1));
        clear_registry(guard);
    }

    #[test]
    fn slots_above_seven_can_never_match() {
        // The mask is `(1 << slot) & 0xff`, so bit 8 and up is lost;
        // an ARM register shift of 32..=255 yields 0 outright.
        let guard = with_registry(&[(1, 0x500, 0xff)]);
        assert_eq!(find_for_slot(7, 0x500), record(1));
        assert_eq!(find_for_slot(8, 0x500), ptr::null_mut(), "bit 8 truncated away");
        assert_eq!(find_for_slot(31, 0x500), ptr::null_mut());
        assert_eq!(find_for_slot(32, 0x500), ptr::null_mut(), "arm_lsl yields 0");
        assert_eq!(find_for_slot(255, 0x500), ptr::null_mut());
        clear_registry(guard);
    }

    #[test]
    fn the_shift_amount_is_only_the_bottom_byte() {
        // `lsl r1, r3, r1` reads r1's low byte: 0x100 shifts by 0.
        let guard = with_registry(&[(2, 0x600, 0b0000_0001)]);
        assert_eq!(find_for_slot(0x100, 0x600), record(2), "0x100 & 0xff == 0");
        clear_registry(guard);
    }

    #[test]
    fn the_id_compare_is_zero_extended_from_16_bits() {
        let guard = with_registry(&[(5, 0x1234, 0b0000_0001)]);
        assert_eq!(find_for_slot(0, 0x1234), record(5));
        assert_eq!(find_for_slot(0, 0x1_1234), ptr::null_mut(), "high argument bits must be 0");
        clear_registry(guard);
    }

    #[test]
    fn the_this_argument_is_ignored() {
        let guard = with_registry(&[(11, 0x700, 0b0000_0001)]);
        let mut anything = [0u8; 4];
        unsafe {
            assert_eq!(registry_find_for_slot(anything.as_mut_ptr(), 0, 0x700), record(11));
            assert_eq!(registry_find_for_slot(ptr::null_mut(), 0, 0x700), record(11));
        }
        clear_registry(guard);
    }

    #[test]
    fn the_table_base_comes_from_the_handles_first_word() {
        let mut a =
            [slot(1, 0), slot(2, 0), slot(3, 0), slot(4, 0), slot(5, 0), slot(6, 0)];
        let mut b =
            [slot(7, 0), slot(8, 0), slot(9, 0), slot(10, 0), slot(11, 0), slot(12, 0)];
        let mut handle = a.as_mut_ptr();
        unsafe {
            assert_eq!(table6_find_by_key(&handle, 3), a.as_mut_ptr().add(2));
            handle = b.as_mut_ptr();
            assert_eq!(table6_find_by_key(&handle, 3), ptr::null_mut());
            assert_eq!(table6_find_by_key(&handle, 9), b.as_mut_ptr().add(2));
        }
    }
}
