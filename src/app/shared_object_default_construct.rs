//! Default constructor for the 0xdc-byte shared object used by object layouts.
//!
//! Original: `FUN_0827bc9c` @ 0x0827bc9c. True extent: 132 bytes to the
//! next function at 0x0827bd20 (124 instruction bytes, 8 literal bytes).
//! Raw aligned A32 decoding verifies two incoming plain BLs, five outgoing
//! plain BLs, and zero predicated BLs in either direction.
//!
//! Initializes the refcounted base, installs the derived vtable and selector,
//! then initializes two sparse fixed-point records and two three-word records.
//! Installs embedded vtables and pointers to the three-word records, clears
//! the remaining control words, and returns the original allocation in r0.
//! Ghidra's void/no-argument signature is incorrect. Field identities beyond
//! these observed roles are not established.
//!
//! Deliberate deviations: none. Pointer fields remain target-width u32 words;
//! host addresses are truncated when stored, never dereferenced by this port.

use crate::app::fixed_value::refcounted_base_init;
use crate::util::fixed_point_record_init::fixed_point_record_init;
use crate::util::zero_three_words::zero_three_words;

/// # Safety
/// `storage` must be non-null, four-byte aligned, and writable for 0xdc bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn shared_object_default_construct(storage: *mut u32) -> *mut u32 {
    refcounted_base_init(storage.cast());
    storage.write(0x0898_7d60);
    storage.add(2).write(1);
    storage.add(9).write(0);
    let first = fixed_point_record_init(storage.add(22));
    let first_values = zero_three_words(first.add(10));
    first_values.add(4).write(0);
    let second = fixed_point_record_init(first_values.add(6));
    let second_values = zero_three_words(second.add(10));
    second_values.add(4).write(0);
    storage.add(25).write(0x08a7_9784);
    storage.add(41).write(0x08a7_9784);
    storage.add(22).write(first_values as usize as u32);
    storage.add(38).write(second_values as usize as u32);
    storage.add(21).write(0);
    storage.add(37).write(0);
    storage.add(53).write(0);
    storage.add(54).write(0);
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_full_layout_preserving_holes_neighbors_and_return_identity() {
        for fill in [0, u32::MAX, 0x1234_5678, 0x8000_0001] {
            let mut words = [fill; 57];
            let storage = unsafe { words.as_mut_ptr().add(1) };
            let mut expected = words;
            let object = &mut expected[1..56];
            object[0] = 0x0898_7d60;
            object[2] = 1;
            for i in [5, 9, 21, 23, 26, 32, 33, 34, 36, 37, 39, 42,
                48, 49, 50, 52, 53, 54] { object[i] = 0; }
            for i in [27, 28, 29, 30, 43, 44, 45, 46] { object[i] = 0x10000; }
            for i in [31, 47] {
                let mut bytes = fill.to_ne_bytes();
                bytes[0] = 0;
                object[i] = u32::from_ne_bytes(bytes);
            }
            object[25] = 0x08a7_9784;
            object[41] = 0x08a7_9784;
            object[22] = unsafe { storage.add(32) } as usize as u32;
            object[38] = unsafe { storage.add(48) } as usize as u32;
            assert_eq!(unsafe { shared_object_default_construct(storage) }, storage);
            assert_eq!(words, expected);
            assert_eq!(unsafe { shared_object_default_construct(storage) }, storage);
            assert_eq!(words, expected);
        }
    }
}
