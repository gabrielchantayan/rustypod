//! Remove a value by virtual lookup: `FUN_083d1560` @ `0x083d1560`.
//!
//! True extent: 64 bytes, [0x083d1560, 0x083d15a0), sixteen A32 words
//! ending in POP; the next function starts with an independent PUSH.
//! Raw whole-image decoding finds one inbound plain BL (0x08136490), no
//! predicated BLs, and no outgoing direct BLs. The body dispatches BLX via
//! +0x4c and BLXNE via +0x2c. Pass a stack copy of the value to lookup;
//! unless the result is exactly -1, reload the vtable and erase that index.
//! Return the lookup result, ignoring erase's return. Concrete virtual
//! identities remain unresolved. The caller marks its array changed only
//! for a nonnegative result.
//!
//! Deliberate deviations: reuse the existing byte-identical 0x083d1cc0
//! implementation through a Rust tail call instead of duplicating its body.
//! Native vtable pointers/slots widen on hosts, retaining four-byte slots on
//! ARM. Incidental r2/r3 register residue is not an argument. No behavioral
//! deviations; the temporary value remains writable and vtable reload matters.
//! ARM review: match.py shows a four-instruction wrapper ending in a tail
//! branch. The reused implementation has 21 instructions versus stock's 16,
//! preserving both slot loads, the vtable reload, -1 test, and saved return;
//! LLVM substitutes an explicit stack store and BEQ for predicated dispatch.

use super::element_array_remove_value::{element_array_remove_value, ElementArrayRemoveValue};

/// # Safety
/// The receiver must have valid lookup (+0x4c) and erase (+0x2c) vtable
/// entries. Lookup must not retain the temporary value pointer. Any result
/// other than -1 must be accepted by the receiver's post-lookup erase entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn observable_array_remove_value(
    this: *mut ElementArrayRemoveValue, value: u32,
) -> i32 {
    element_array_remove_value(this, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::element_array_remove_value::ElementArrayRemoveValueVtable;

    #[repr(C)]
    struct Collection {
        receiver: ElementArrayRemoveValue,
        values: [u32; 3],
        count: usize,
    }

    unsafe extern "C" fn lookup(this: *mut ElementArrayRemoveValue, value: *mut u32) -> i32 {
        let collection = &mut *this.cast::<Collection>();
        let index = collection.values[..collection.count].iter().position(|v| *v == *value);
        *value = 123; // Mutation applies only to the wrapper's stack copy.
        index.map_or(-1, |i| i as i32)
    }

    unsafe extern "C" fn erase(this: *mut ElementArrayRemoveValue, index: i32) -> i32 {
        let collection = &mut *this.cast::<Collection>();
        collection.values.copy_within(index as usize + 1..collection.count, index as usize);
        collection.count -= 1;
        -99
    }

    #[test]
    fn removes_first_duplicate_zero_and_maximum_then_preserves_empty_collection() {
        let table = ElementArrayRemoveValueVtable { unresolved_00_28: [0; 11], erase_at: erase,
            unresolved_30_48: [0; 7], index_of: lookup };
        let mut collection = Collection { receiver: ElementArrayRemoveValue { vtable: &table },
            values: [0, u32::MAX, 0], count: 3 };
        for (value, result, remaining) in [
            (42, -1, &[0, u32::MAX, 0][..]),
            (0, 0, &[u32::MAX, 0][..]),
            (0, 1, &[u32::MAX][..]),
            (u32::MAX, 0, &[][..]),
            (0, -1, &[][..]),
        ] {
            assert_eq!(unsafe { observable_array_remove_value(&mut collection.receiver, value) }, result);
            assert_eq!(&collection.values[..collection.count], remaining);
        }
    }
}
