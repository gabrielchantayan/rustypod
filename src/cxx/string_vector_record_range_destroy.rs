//! `cxx_string_vector_record_range_destroy` — original: `FUN_083e2230` @
//! 0x083e2230 (48 bytes).
//!
//! Raw ARM establishes the exact extent 0x083e2230..0x083e2260: the next
//! independently linked function (pushing r4..r8) starts at 0x083e2260. The
//! twelve words are: push {r4,r5,r6,lr}; save r2 (end) and r1 (begin) into
//! r5/r4; branch into the loop tail; then per record: `add r0, r4, #4`;
//! `bl cxx_string_vector_destruct` @ 0x083e5b88; `sub r0, r0, #4` (the
//! returned vector pointer minus four bytes recovers the record base);
//! `bl cxx_string_release` @ 0x083d8b04; `add r4, r4, #0x10`;
//! `cmp r4, r5`; `bne` the loop; finally pop {r4,r5,r6,pc}. r0 (param_1) is
//! never used. Decoding every ARM B/BL word in osos.dec verifies exactly two
//! unconditional `bl` calls inside, no predicated calls, and four direct,
//! unconditional `bl` callers at 0x08197c3c, 0x083e237c, 0x083e2640, and
//! 0x083e26b4; there are no tail branches.
//!
//! Algorithm: walk the half-open `[begin, end)` range of sixteen-byte records
//! `{COW string slot @ +0, CxxStringVector @ +4}` in address order; for each
//! record destruct the embedded string vector, then release the record's COW
//! string slot.
//!
//! # Deliberate deviation
//!
//! None; both call boundaries are preserved. Host tests inject recorders
//! through `cxx_string_vector_record_range_destroy_with` so they can observe
//! the ordered record walk without synthetic COW-string storage.

use crate::cxx::string::cxx_string_release;
use crate::cxx::string_vector_destruct::{cxx_string_vector_destruct, CxxStringVector};

type VectorDestruct = unsafe extern "C" fn(*mut CxxStringVector) -> *mut CxxStringVector;
type StringRelease = unsafe extern "C" fn(*mut *mut u8);

/// Record stride in target bytes: one four-byte COW string slot plus the
/// twelve-byte vector descriptor.
const RECORD_STRIDE: usize = 0x10;

/// Destroys every `{string, vector}` record in `[begin, end)`. The first
/// argument matches the original's ignored r0. `begin` and `end` are record
/// base addresses; on ARMv5 the vector lives four bytes into each record.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_vector_record_range_destroy")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_record_range_destroy(
    _ignored: *mut u8,
    begin: *mut u8,
    end: *mut u8,
) {
    unsafe {
        cxx_string_vector_record_range_destroy_with(
            begin,
            end,
            cxx_string_vector_destruct,
            cxx_string_release,
        )
    }
}

/// Separates the two verified callees so host tests can observe the record
/// walk, including the return-minus-four recovery of each record base,
/// without dereferencing synthetic COW-string storage.
#[inline(always)]
unsafe fn cxx_string_vector_record_range_destroy_with(
    begin: *mut u8,
    end: *mut u8,
    destruct_vector: VectorDestruct,
    release_string: StringRelease,
) {
    unsafe {
        let mut current = begin;
        while current != end {
            let vector = destruct_vector(current.add(4) as *mut CxxStringVector);
            release_string((vector as *mut u8).sub(4) as *mut *mut u8);
            current = current.add(RECORD_STRIDE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DESTRUCT_COUNT: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static DESTRUCTED_VECTORS: [AtomicUsize; 4] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];
    static RELEASED_SLOTS: [AtomicUsize; 4] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    unsafe extern "C" fn record_vector_destruct(
        vector: *mut CxxStringVector,
    ) -> *mut CxxStringVector {
        let index = DESTRUCT_COUNT.fetch_add(1, Ordering::SeqCst);
        DESTRUCTED_VECTORS[index].store(vector as usize, Ordering::SeqCst);
        vector
    }

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        let index = RELEASE_COUNT.fetch_add(1, Ordering::SeqCst);
        RELEASED_SLOTS[index].store(slot as usize, Ordering::SeqCst);
    }

    fn reset_observations() {
        DESTRUCT_COUNT.store(0, Ordering::SeqCst);
        RELEASE_COUNT.store(0, Ordering::SeqCst);
        for slot in &DESTRUCTED_VECTORS {
            slot.store(0, Ordering::SeqCst);
        }
        for slot in &RELEASED_SLOTS {
            slot.store(0, Ordering::SeqCst);
        }
    }

    #[test]
    fn destroys_each_record_in_address_order() {
        let mut records = [0u8; 3 * RECORD_STRIDE];
        reset_observations();

        unsafe {
            cxx_string_vector_record_range_destroy_with(
                records.as_mut_ptr(),
                records.as_mut_ptr().add(3 * RECORD_STRIDE),
                record_vector_destruct,
                record_string_release,
            )
        };

        assert_eq!(DESTRUCT_COUNT.load(Ordering::SeqCst), 3);
        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 3);
        for index in 0..3 {
            let record = unsafe { records.as_mut_ptr().add(index * RECORD_STRIDE) } as usize;
            assert_eq!(DESTRUCTED_VECTORS[index].load(Ordering::SeqCst), record + 4);
            assert_eq!(RELEASED_SLOTS[index].load(Ordering::SeqCst), record);
        }
    }

    #[test]
    fn empty_range_destroys_nothing() {
        let mut records = [0u8; RECORD_STRIDE];
        reset_observations();

        unsafe {
            cxx_string_vector_record_range_destroy_with(
                records.as_mut_ptr(),
                records.as_mut_ptr(),
                record_vector_destruct,
                record_string_release,
            )
        };

        assert_eq!(DESTRUCT_COUNT.load(Ordering::SeqCst), 0);
        assert_eq!(RELEASE_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn vector_destruct_return_drives_release_argument() {
        let mut records = [0u8; RECORD_STRIDE];
        reset_observations();

        unsafe {
            cxx_string_vector_record_range_destroy_with(
                records.as_mut_ptr(),
                records.as_mut_ptr().add(RECORD_STRIDE),
                record_vector_destruct,
                record_string_release,
            )
        };

        // The recorder returns its argument, so release must observe exactly
        // the record base: (vector + 0) - 4.
        assert_eq!(
            RELEASED_SLOTS[0].load(Ordering::SeqCst),
            records.as_mut_ptr() as usize
        );
    }
}
