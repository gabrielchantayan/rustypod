//! Remove a cell value by virtual lookup: `FUN_083d0bec` @ `0x083d0bec`.
//!
//! True extent: 64 bytes, [0x083d0bec, 0x083d0c2c), sixteen A32 words;
//! the next independent function starts with PUSH {r4,lr}. Whole-image raw
//! decoding finds one inbound plain BL at 0x081fb54c, zero predicated BLs.
//! Outbound: zero plain/predicated BLs, one BLX via +0x4c and one BLXNE
//! via +0x2c. Lookup receives a writable stack copy of the value. Unless
//! its result is exactly -1, reload the vtable and erase that index; return
//! the lookup result, ignoring erase's return. The caller operates on its
//! observable-array subobject at +0x1c while releasing a containing cell.
//! Concrete virtual method identities remain unresolved.
//!
//! Deliberate deviations: reuse the identical element_array_remove_value
//! algorithm through a Rust tail call. Native pointer/usize slots widen on
//! hosts but remain four bytes apart on ARM. Incidental r2/r3 contents and
//! spilled receiver storage are not extra arguments, despite Ghidra's C.
//! ARM review: LLVM intentionally folds this wrapper into the exported
//! attached_observable_array_remove_value symbol (same section, value, size).
//! match.py cannot locate the alias's disassembly label; comparing the shared
//! label reports a four-instruction tail wrapper. Its shared removal body
//! has 21 instructions, preserving both slot loads, the vtable reload, exact
//! -1 comparison and saved return; LLVM uses BEQ rather than BLXNE.

use super::element_array_remove_value::{element_array_remove_value, ElementArrayRemoveValue};

/// # Safety
/// The receiver must provide lookup (+0x4c), which must not retain the
/// temporary value pointer, and a valid post-lookup erase (+0x2c) method
/// accepting every lookup result other than -1.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn observable_cell_array_remove_value(
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
        replacement: *const ElementArrayRemoveValueVtable,
        values: [u32; 3],
        count: usize,
    }

    unsafe extern "C" fn lookup(this: *mut ElementArrayRemoveValue, value: *mut u32) -> i32 {
        let collection = &mut *this.cast::<Collection>();
        let index = collection.values[..collection.count].iter().position(|v| *v == *value);
        *value = 42;
        collection.receiver.vtable = collection.replacement;
        index.map_or(-1, |i| i as i32)
    }

    unsafe extern "C" fn erase(this: *mut ElementArrayRemoveValue, index: i32) -> i32 {
        let collection = &mut *this.cast::<Collection>();
        collection.values.copy_within(index as usize + 1..collection.count, index as usize);
        collection.count -= 1;
        -99
    }

    unsafe extern "C" fn stale_erase(_: *mut ElementArrayRemoveValue, _: i32) -> i32 {
        panic!("erase must reload the post-lookup vtable")
    }

    #[test]
    fn removes_first_duplicate_using_replaced_vtable_and_preserves_absent_or_empty_array() {
        let replacement = ElementArrayRemoveValueVtable { unresolved_00_28: [0; 11], erase_at: erase,
            unresolved_30_48: [0; 7], index_of: lookup };
        let initial = ElementArrayRemoveValueVtable { erase_at: stale_erase, ..replacement };
        let mut collection = Collection { receiver: ElementArrayRemoveValue { vtable: &initial },
            replacement: &replacement, values: [u32::MAX, 0, u32::MAX], count: 3 };
        for (value, result, remaining) in [
            (7, -1, &[u32::MAX, 0, u32::MAX][..]),
            (u32::MAX, 0, &[0, u32::MAX][..]),
            (u32::MAX, 1, &[0][..]),
            (0, 0, &[][..]),
            (0, -1, &[][..]),
        ] {
            collection.receiver.vtable = &initial;
            assert_eq!(unsafe { observable_cell_array_remove_value(&mut collection.receiver, value) }, result);
            assert_eq!(&collection.values[..collection.count], remaining);
        }
    }
}
