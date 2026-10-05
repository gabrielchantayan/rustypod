//! Refcounted value-array default constructor — `FUN_081af4c8` @ 0x081af4c8.
//! True extent: 40 bytes (36 instruction bytes and the vtable literal at
//! 0x081af4ec); next function starts at 0x081af4f0. Verified inbound calls:
//! two plain BLs (0x081567c8, 0x08199e4c), zero predicated BLs. One outgoing
//! plain BL to the existing refcounted base constructor, no predicated BLs.
//!
//! Both callers allocate 0x28 bytes. Initialize the refcounted prefix,
//! replace its vtable with 0x0898b63c, clear the count at +0x1c and the
//! two array-storage words at +0x20/+0x24, and return the original pointer.
//! The destructor at 0x081af508 walks +0x24 backwards using +0x1c, releases
//! non-null entries, then frees both storage words. Other fields stay dirty.
//! Deliberate deviations: use target-width words on hosts and preserve the
//! vtable as an address constant, following the existing base constructor.
//! LLVM may save this across the base call rather than rely on preserved r0.

use super::fixed_value::{refcounted_base_init, FixedValue};

pub const REFCOUNTED_VALUE_ARRAY_VTABLE: u32 = 0x0898_b63c;

/// Initialize a caller-owned refcounted value-array object and return it.
///
/// # Safety
/// `this` must point to at least ten initialized, writable, aligned u32 words.
/// The constructor does not release prior contents or validate the pointer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_value_array_default_init(this: *mut u32) -> *mut u32 {
    refcounted_base_init(this.cast::<FixedValue>());
    this.write_volatile(REFCOUNTED_VALUE_ARRAY_VTABLE);
    this.add(7).write_volatile(0);
    this.add(8).write_volatile(0);
    this.add(9).write_volatile(0);
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_holes_neighbors_and_pointer_on_reinitialization() {
        for seed in [0, u32::MAX, 0x1234_5678, 3, 0xffff_fffc] {
            let mut storage = [seed; 12];
            storage[0] = 0xcafe_babe;
            storage[11] = 0xdead_beef;
            for i in 1..11 {
                storage[i] = seed.rotate_left(i as u32);
            }
            let before = storage;
            let object = unsafe { storage.as_mut_ptr().add(1) };
            for _ in 0..2 {
                assert_eq!(unsafe { refcounted_value_array_default_init(object) }, object);
                let mut expected = before;
                expected[1] = REFCOUNTED_VALUE_ARRAY_VTABLE;
                expected[6] = 0;
                expected[8] = 0;
                expected[9] = 0;
                expected[10] = 0;
                assert_eq!(storage, expected);
            }
        }
    }
}
