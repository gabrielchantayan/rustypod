//! Slot-array index bounds check — original: `FUN_083d4db8` @ 0x083d4db8
//! (**24 bytes**, 0x083d4db8..0x083d4dd0; the next function is the empty
//! `bx lr` at 0x083d4dd0, then the owning container's insert routine at
//! 0x083d4dd4, so Ghidra's 24 is exactly right).
//!
//! Raw ARM:
//!
//! ```text
//! 083d4db8  cmp   r1,#0x0
//! 083d4dbc  ldrge r0,[r0,#0x4]   @ capacity
//! 083d4dc0  cmpge r0,r1
//! 083d4dc4  movle r0,#0x0
//! 083d4dc8  movgt r0,#0x1
//! 083d4dcc  bx    lr
//! ```
//!
//! **4 direct `bl` call sites, 0 predicated**, verified by decoding every
//! ARM B/BL word in `work/firmware/osos.dec`: 0x081ef1e0 (a registry's
//! add path, gating a vtable-slot release on failure), 0x081ef308 (the
//! checked element getter `index in bounds ? storage[index] : NULL`),
//! 0x083d4e54 (insert, validating the free-slot scan result which is -1
//! when full), and 0x083d4f38 (remove-at-index, gating a virtual release
//! and slot clear).
//!
//! Algorithm: return 1 iff `0 <= index < this.capacity`, else 0. The
//! capacity word at +0x04 is only loaded when `index >= 0`; a negative
//! index short-circuits to 0 with no load at all (the `movle` executes on
//! the flags of `cmp r1,#0`). The owning container is the pointer slot
//! array whose insert routine at 0x083d4dd4 lays out +0x00 storage,
//! +0x04 capacity, +0x08 occupied count, +0x10 growth multiplier, and
//! grows by `realloc(storage, capacity * multiplier * 4)`; the bound is
//! the capacity (allocated slots), not the occupied count, because the
//! array keeps holes and insert stores into a freed slot. This is the
//! same `{data, slots, used, options, growth, tracker_label}` 0x18-byte
//! object-slot-array template as the nine `element_table` containers in
//! `app/element_table` (the inert Tracker instrumentation at 0x083d4dd0
//! is the same four-byte `bx lr` no-op); this bounds check is the
//! template's generic `0 <= index < slots` guard.
//!
//! Deliberate deviation: none in behavior. The result is `i32` 0/1 as in
//! the original (`movgt r0,#1` / `movle r0,#0`), not a Rust `bool`.

/// The pointer slot array owned by the container at 0x083d4dd4. Only the
/// capacity field is read by this bounds check; the rest documents the
/// layout established by the sibling insert/grow routines.
#[repr(C)]
pub struct SlotArray {
    /// +0x00: element storage base (`u32`-word array of object pointers).
    pub storage: u32,
    /// +0x04: allocated slot count; the exclusive bounds-check limit.
    pub capacity: i32,
    /// +0x08: occupied (non-NULL) slot count.
    pub count: i32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(SlotArray, storage)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(SlotArray, capacity)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(SlotArray, count)];

/// slot_array_index_in_bounds — original: `FUN_083d4db8` @ `0x083d4db8`
/// (24 bytes; 4 plain `bl` call sites, 0 predicated, binary-scanned).
/// See the module header for the raw listing and algorithm.
///
/// Returns 1 when `0 <= index < this.capacity`, else 0.
///
/// # Safety
///
/// When `index >= 0`, `this` must point to a readable slot array; like the
/// original, `this` is never NULL-checked and never dereferenced for a
/// negative `index` (the `ldrge` is predicated off), so a negative-index
/// call is safe with any `this` value, matching retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn slot_array_index_in_bounds(
    this: *const SlotArray,
    index: i32,
) -> i32 {
    if index < 0 {
        return 0;
    }
    let capacity = core::ptr::read_volatile(core::ptr::addr_of!((*this).capacity));
    (capacity > index) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn array(capacity: i32) -> SlotArray {
        SlotArray { storage: 0, capacity, count: 0 }
    }

    #[test]
    fn accepts_every_index_below_capacity() {
        let a = array(4);
        for index in 0..4 {
            assert_eq!(unsafe { slot_array_index_in_bounds(&a, index) }, 1);
        }
    }

    #[test]
    fn rejects_index_at_and_past_capacity() {
        let a = array(4);
        assert_eq!(unsafe { slot_array_index_in_bounds(&a, 4) }, 0);
        assert_eq!(unsafe { slot_array_index_in_bounds(&a, 5) }, 0);
        assert_eq!(unsafe { slot_array_index_in_bounds(&a, i32::MAX) }, 0);
    }

    #[test]
    fn rejects_negative_index_without_dereferencing() {
        // The predicated ldrge never fires for index < 0: the original
        // tolerates a garbage `this` here (insert passes -1 when its
        // free-slot scan fails), so prove the port does too.
        assert_eq!(unsafe { slot_array_index_in_bounds(core::ptr::null(), -1) }, 0);
        assert_eq!(unsafe { slot_array_index_in_bounds(core::ptr::null(), i32::MIN) }, 0);
    }

    #[test]
    fn empty_array_rejects_everything() {
        let a = array(0);
        assert_eq!(unsafe { slot_array_index_in_bounds(&a, 0) }, 0);
        assert_eq!(unsafe { slot_array_index_in_bounds(&a, -1) }, 0);
    }

    #[test]
    fn negative_capacity_rejects_nonnegative_index() {
        // Uninitialized/stale capacity: cmpge r0,r1 with capacity <= 0
        // can never set GT for index >= 0.
        let a = array(-3);
        assert_eq!(unsafe { slot_array_index_in_bounds(&a, 0) }, 0);
    }
}
