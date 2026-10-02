//! Delete owned array values, then clear the array when ownership is enabled.
//!
//! Original: FUN_0829169c @ 0x0829169c. True extent: 76 bytes through the
//! tail branch at 0x082916e4; next function starts at 0x082916e8. Raw A32
//! verifies two plain outbound BLs, zero predicated BLs, and a tail B to
//! observable_array_clear. Inbound: one plain BL at 0x08291ce8 and one BLNE
//! at 0x082907e8. Ghidra's 72-byte extent and truncated loop are incorrect.
//!
//! Test flag +0x48 bit 27. When set, snapshot signed count +0x1e4, visit
//! indices [0,count) of the embedded array at +0x1e0, and tag-2 delete the
//! pointer word returned by array_element_at. Always clear the enabled array,
//! including zero/negative counts. No destructor or pointer-slot zeroing.
//!
//! Deviations: Rust calls the existing clear port instead of a tail branch.
//! Host-only operations avoid incompatible native-width array layouts; target
//! calls all three existing ports directly. The containing class is unnamed.

// The existing ARM clear port is a global_asm export, not a Rust item.
#[cfg(target_os = "none")]
extern "C" {
    fn observable_array_clear(array: *mut crate::cxx::observable_array::ObservableArray);
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct FlaggedOwnedArrayClearOps {
    pub element_at: unsafe extern "C" fn(*mut u8, i32) -> *const u32,
    pub delete: unsafe extern "C" fn(*mut u8),
    pub clear: unsafe extern "C" fn(*mut u8),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_element_at(_: *mut u8, _: i32) -> *const u32 {
    panic!("install flagged owned array host operations")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_operation(_: *mut u8) {
    panic!("install flagged owned array host operations")
}
#[cfg(not(target_os = "none"))]
pub static mut FLAGGED_OWNED_ARRAY_CLEAR_OPS: FlaggedOwnedArrayClearOps = FlaggedOwnedArrayClearOps {
    element_at: missing_element_at, delete: missing_operation, clear: missing_operation,
};

/// # Safety
/// `owner` is word-aligned and readable through +0x48. If bit 27 is set,
/// its array at +0x1e0 and all indexed pointer words must satisfy the existing
/// array accessor, deallocator, and virtual clear contracts. No NULL guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn flagged_owned_array_clear(owner: *mut u8) {
    if owner.add(0x48).cast::<u32>().read_volatile() & 0x0800_0000 == 0 {
        return;
    }
    let count = owner.add(0x1e4).cast::<i32>().read_volatile();
    let array = owner.add(0x1e0);
    let mut index = 0;
    while index < count {
        #[cfg(target_os = "none")]
        {
            let slot = crate::cxx::array_element_at::array_element_at(array.cast(), index);
            let value = (slot as *const u32).read_volatile();
            crate::heap::veneers::operator_delete(value as *mut u8);
        }
        #[cfg(not(target_os = "none"))]
        {
            let ops = core::ptr::addr_of!(FLAGGED_OWNED_ARRAY_CLEAR_OPS).read_volatile();
            let value = (ops.element_at)(array, index).read_volatile();
            (ops.delete)(value as usize as *mut u8);
        }
        index += 1;
    }
    #[cfg(target_os = "none")]
    observable_array_clear(array.cast());
    #[cfg(not(target_os = "none"))]
    (core::ptr::addr_of!(FLAGGED_OWNED_ARRAY_CLEAR_OPS).read_volatile().clear)(array);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut SLOTS: [u32; 4] = [0; 4];
    static mut DELETED: [usize; 4] = [0; 4];
    static mut VISITS: usize = 0;
    static mut CLEARS: usize = 0;
    static mut ARRAY: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn element_at(array: *mut u8, index: i32) -> *const u32 {
        assert_eq!(array, ARRAY);
        assert_eq!(index as usize, VISITS);
        core::ptr::addr_of!(SLOTS).cast::<u32>().add(index as usize)
    }
    unsafe extern "C" fn delete(value: *mut u8) {
        DELETED[VISITS] = value as usize;
        VISITS += 1;
        // Callback mutation must not shorten the snapshotted iteration bound.
        ARRAY.add(4).cast::<i32>().write(0);
    }
    unsafe extern "C" fn clear(array: *mut u8) {
        assert_eq!(array, ARRAY);
        CLEARS += 1;
        array.add(4).cast::<i32>().write(0);
    }

    #[test]
    fn ownership_gate_signed_counts_and_snapshot_order() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = core::ptr::addr_of!(FLAGGED_OWNED_ARRAY_CLEAR_OPS).read();
            FLAGGED_OWNED_ARRAY_CLEAR_OPS = FlaggedOwnedArrayClearOps { element_at, delete, clear };
            for (flags, count, expected) in [
                (0x07ff_ffff, 4, 0), (0, i32::MIN, 0),
                (0x0800_0000, i32::MIN, 0), (0x0800_0000, -1, 0),
                (0x0800_0000, 0, 0), (0x0800_0000, 1, 1),
                (0xffff_ffff, 4, 4),
            ] {
                let mut owner = [0u32; 0x200 / 4];
                owner[0x48 / 4] = flags;
                owner[0x1e4 / 4] = count as u32;
                ARRAY = owner.as_mut_ptr().cast::<u8>().add(0x1e0);
                SLOTS = [0x1234, 0, 0x5678, 0x1234];
                DELETED = [usize::MAX; 4];
                VISITS = 0;
                CLEARS = 0;
                flagged_owned_array_clear(owner.as_mut_ptr().cast());
                assert_eq!(VISITS, expected);
                assert_eq!(CLEARS, usize::from(flags & 0x0800_0000 != 0));
                for i in 0..expected { assert_eq!(DELETED[i], SLOTS[i] as usize); }
                assert_eq!(owner[0x48 / 4], flags);
                assert_eq!(owner[0x1e4 / 4], if CLEARS == 0 { count as u32 } else { 0 });
                assert_eq!(core::ptr::addr_of!(SLOTS).read(), [0x1234, 0, 0x5678, 0x1234]);
            }
            FLAGGED_OWNED_ARRAY_CLEAR_OPS = saved;
        }
    }
}
