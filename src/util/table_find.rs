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

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

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
