//! Remove a value by virtual lookup: `FUN_083d1cc0` @ `0x083d1cc0`.
//!
//! True extent: 64 instruction bytes, [0x083d1cc0, 0x083d1d00); the next
//! function begins with an independent PUSH. Raw A32 word decoding finds
//! one incoming plain BL at 0x08211c94, zero incoming predicated BLs, zero
//! outgoing plain/predicated BLs, one BLX (+0x4c), and one BLXNE (+0x2c).
//! Pass a stack copy of the value to the lookup slot. Unless its result is
//! exactly -1, reload the receiver's vtable and erase at that index. Return
//! the original lookup result, ignoring erase's result. The caller removes
//! a node pointer from its array subobject after unlinking the node's payload.
//! Concrete virtual method identities are not assumed.
//!
//! Deliberate deviations: native pointers/usize slots widen on hosts; ARM
//! slots remain four bytes apart. Incidental r2/r3 and spilled receiver words
//! are not modeled as arguments (Ghidra's extra arguments are register residue).
//! ARM codegen review: match.py reports 21 instructions versus retailOS's 16.
//! LLVM uses an explicit stack store/frame and BEQ instead of predicated
//! erase instructions; both virtual slot loads, vtable reload, -1 comparison,
//! and saved lookup-result return match the original structure.

pub type ElementArrayLookup = unsafe extern "C" fn(*mut ElementArrayRemoveValue, *mut u32) -> i32;
pub type ElementArrayErase = unsafe extern "C" fn(*mut ElementArrayRemoveValue, i32) -> i32;

#[repr(C)]
pub struct ElementArrayRemoveValueVtable {
    pub unresolved_00_28: [usize; 11],
    pub erase_at: ElementArrayErase,
    pub unresolved_30_48: [usize; 7],
    pub index_of: ElementArrayLookup,
}

#[repr(C)]
pub struct ElementArrayRemoveValue {
    pub vtable: *const ElementArrayRemoveValueVtable,
}

/// # Safety
/// The receiver and its vtable must be valid. Lookup must accept a temporary
/// mutable word and not retain it; if it returns anything except -1, the
/// receiver's resulting vtable must provide an erase callback for that index.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn element_array_remove_value(this: *mut ElementArrayRemoveValue, mut value: u32) -> i32 {
    let lookup = (*(*this).vtable).index_of;
    let index = lookup(this, &mut value);
    if index != -1 {
        let erase = (*(*this).vtable).erase_at;
        erase(this, index);
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        receiver: ElementArrayRemoveValue,
        replacement: *const ElementArrayRemoveValueVtable,
        values: [u32; 4],
        count: usize,
        lookup_result: i32,
        erased: Option<i32>,
    }

    unsafe extern "C" fn lookup(this: *mut ElementArrayRemoveValue, value: *mut u32) -> i32 {
        let fixture = &mut *this.cast::<Fixture>();
        let found = fixture.values[..fixture.count].iter().position(|v| *v == *value);
        *value = 0; // The callback may modify the local argument, not the caller's word.
        (*this).vtable = fixture.replacement;
        if found.is_some() { fixture.lookup_result } else { -1 }
    }

    unsafe extern "C" fn erase(this: *mut ElementArrayRemoveValue, index: i32) -> i32 {
        let fixture = &mut *this.cast::<Fixture>();
        fixture.erased = Some(index);
        if index >= 0 && (index as usize) < fixture.count {
            fixture.values.copy_within(index as usize + 1..fixture.count, index as usize);
            fixture.count -= 1;
        }
        -77 // Must never replace the lookup result.
    }

    unsafe extern "C" fn stale_erase(_: *mut ElementArrayRemoveValue, _: i32) -> i32 {
        panic!("erase used the pre-lookup vtable")
    }

    fn table(erase_at: ElementArrayErase) -> ElementArrayRemoveValueVtable {
        ElementArrayRemoveValueVtable { unresolved_00_28: [0; 11], erase_at,
            unresolved_30_48: [0; 7], index_of: lookup }
    }

    #[test]
    fn removes_first_duplicate_and_preserves_absent_collection() {
        let initial = table(stale_erase);
        let replacement = table(erase);
        for (value, index, expected, count) in [
            (8, 1, [7, 8, 9, 9], 3),
            (7, 0, [8, 8, 9, 9], 3),
            (9, 3, [7, 8, 8, 9], 3),
            (0, -1, [7, 8, 8, 9], 4),
            (u32::MAX, -1, [7, 8, 8, 9], 4),
        ] {
            let mut fixture = Fixture { receiver: ElementArrayRemoveValue { vtable: &initial },
                replacement: &replacement, values: [7, 8, 8, 9], count: 4,
                lookup_result: index, erased: None };
            assert_eq!(unsafe { element_array_remove_value(&mut fixture.receiver, value) }, index);
            assert_eq!(fixture.values, expected);
            assert_eq!(fixture.count, count);
            assert_eq!(fixture.erased, if index == -1 { None } else { Some(index) });
        }
    }

    #[test]
    fn only_minus_one_suppresses_erase_and_all_other_results_pass_through() {
        let initial = table(stale_erase);
        let replacement = table(erase);
        for index in [-1, -2, i32::MIN, i32::MAX] {
            let mut fixture = Fixture { receiver: ElementArrayRemoveValue { vtable: &initial },
                replacement: &replacement, values: [u32::MAX, 0, 0, 0], count: 1,
                lookup_result: index, erased: None };
            assert_eq!(unsafe { element_array_remove_value(&mut fixture.receiver, u32::MAX) }, index);
            assert_eq!(fixture.erased, if index == -1 { None } else { Some(index) });
            assert_eq!(fixture.values[0], u32::MAX);
            assert_eq!(fixture.count, 1);
        }
    }
}
