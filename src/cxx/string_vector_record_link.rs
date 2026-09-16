//! `cxx_string_vector_record_link` — original: `FUN_083c4de0` @ 0x083c4de0
//! (52 bytes).
//!
//! Raw ARM establishes the exact extent 0x083c4de0..0x083c4e14: the next
//! independently linked function (starting `ldr r2,[r1,#0xc]`) begins at
//! 0x083c4e14. The thirteen words are: push {r4,r5,r6,lr}; save owner in r5
//! and record in r4; `ldr r0,[r0,#4]` (owner's slot); `cmp r2,#0`;
//! `str r0,[r1,#0xc]` — unconditional in the raw word 0xe581000c, chaining
//! the old slot occupant into the record; `beq` past the teardown; then
//! `add r0, r4, #0x14`; `bl cxx_string_vector_destruct` @ 0x083e5b88;
//! `sub r0, r0, #4` (the returned vector pointer minus four bytes recovers
//! the record's COW string slot at +0x10); `bl cxx_string_release` @
//! 0x083d8b04; finally `str r4,[r5,#4]` and pop {r4,r5,r6,pc}. Exactly two
//! unconditional `bl` instructions, no predicated calls. Decoding every ARM
//! B/BL word in osos.dec verifies four direct, unconditional `bl` callers:
//! 0x08134f64 and 0x081cdcf8 (flag r2 = 0), 0x083c5340 and 0x083c56e4
//! (flag r2 = 1); there are no tail branches.
//!
//! Algorithm: splice `record` into the owner's pointer slot at +4, chaining
//! the previous occupant into the record's link word at +0xc. When `teardown`
//! is nonzero the record's embedded payload — the CxxStringVector at +0x14
//! and the COW string slot at +0x10 — is destroyed first, in that order; the
//! slot store happens last either way.
//!
//! # Deliberate deviation
//!
//! None in behavior; both call boundaries are preserved. Because
//! `cxx_string_vector_destruct` is visible within the crate, LLVM proves it
//! returns its argument and materializes the release address as
//! `add r0, r4, #0x10` instead of the original `sub r0, r0, #4`; LLVM also
//! pushes a frame pointer the ADS original did not need. Host tests inject
//! recorders
//! through `cxx_string_vector_record_link_with` so they can observe the
//! teardown order and the return-minus-four release argument without
//! synthetic COW-string storage.

use crate::cxx::string::cxx_string_release;
use crate::cxx::string_vector_destruct::{cxx_string_vector_destruct, CxxStringVector};

type VectorDestruct = unsafe extern "C" fn(*mut CxxStringVector) -> *mut CxxStringVector;
type StringRelease = unsafe extern "C" fn(*mut *mut u8);

/// Word offset of the owner's slot that receives the record.
const OWNER_SLOT: usize = 1;
/// Word offset of the record's chain link to the previous occupant.
const RECORD_LINK: usize = 3;
/// Byte offset of the record's embedded CxxStringVector.
const RECORD_VECTOR: usize = 0x14;

/// Links `record` into `owner`'s slot at +4. The previous occupant is stored
/// in the record's link word at +0xc unconditionally. A nonzero `teardown`
/// first destructs the record's string vector at +0x14 and releases its COW
/// string slot at +0x10.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_vector_record_link")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_record_link(
    owner: *mut u8,
    record: *mut u8,
    teardown: i32,
) {
    unsafe {
        cxx_string_vector_record_link_with(
            owner,
            record,
            teardown,
            cxx_string_vector_destruct,
            cxx_string_release,
        )
    }
}

/// Separates the two verified callees so host tests can observe the link
/// stores and the teardown order without dereferencing synthetic COW-string
/// storage.
#[inline(always)]
unsafe fn cxx_string_vector_record_link_with(
    owner: *mut u8,
    record: *mut u8,
    teardown: i32,
    destruct_vector: VectorDestruct,
    release_string: StringRelease,
) {
    unsafe {
        let old = *(owner as *mut *mut u8).add(OWNER_SLOT);
        *(record as *mut *mut u8).add(RECORD_LINK) = old;
        if teardown != 0 {
            let vector = destruct_vector(record.add(RECORD_VECTOR) as *mut CxxStringVector);
            release_string((vector as *mut u8).sub(4) as *mut *mut u8);
        }
        *(owner as *mut *mut u8).add(OWNER_SLOT) = record;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DESTRUCT_ARG: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_ARG: AtomicUsize = AtomicUsize::new(0);
    static STEP: AtomicUsize = AtomicUsize::new(0);
    static DESTRUCT_STEP: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_STEP: AtomicUsize = AtomicUsize::new(0);
    /// Returned by the recorder instead of its argument so the release
    /// argument provably derives from the destruct return value.
    const RETURN_BIAS: usize = 0x40;

    unsafe extern "C" fn record_vector_destruct(
        vector: *mut CxxStringVector,
    ) -> *mut CxxStringVector {
        DESTRUCT_ARG.store(vector as usize, Ordering::SeqCst);
        DESTRUCT_STEP.store(STEP.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        (vector as *mut u8).add(RETURN_BIAS) as *mut CxxStringVector
    }

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        RELEASE_ARG.store(slot as usize, Ordering::SeqCst);
        RELEASE_STEP.store(STEP.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
    }

    fn reset_observations() {
        DESTRUCT_ARG.store(0, Ordering::SeqCst);
        RELEASE_ARG.store(0, Ordering::SeqCst);
        DESTRUCT_STEP.store(usize::MAX, Ordering::SeqCst);
        RELEASE_STEP.store(usize::MAX, Ordering::SeqCst);
        STEP.store(0, Ordering::SeqCst);
    }

    /// Two-word owner stand-in; the record needs four words up to the link
    /// field, plus the vector bytes are never dereferenced by the recorders.
    struct Fixture {
        owner: [usize; 2],
        record: [usize; 7],
    }

    #[test]
    fn flag_zero_links_without_teardown() {
        reset_observations();
        let mut fix = Fixture { owner: [0, 0xaaaa], record: [0; 7] };
        let owner = fix.owner.as_mut_ptr() as *mut u8;
        let record = fix.record.as_mut_ptr() as *mut u8;
        unsafe {
            cxx_string_vector_record_link_with(
                owner,
                record,
                0,
                record_vector_destruct,
                record_string_release,
            );
        }
        assert_eq!(fix.record[3], 0xaaaa, "link word chains the old occupant");
        assert_eq!(fix.owner[1], record as usize, "slot receives the record");
        assert_eq!(DESTRUCT_ARG.load(Ordering::SeqCst), 0, "no vector destruct");
        assert_eq!(RELEASE_ARG.load(Ordering::SeqCst), 0, "no string release");
    }

    #[test]
    fn flag_one_tears_down_then_links() {
        reset_observations();
        let mut fix = Fixture { owner: [0, 0xbbbb], record: [0; 7] };
        let owner = fix.owner.as_mut_ptr() as *mut u8;
        let record = fix.record.as_mut_ptr() as *mut u8;
        unsafe {
            cxx_string_vector_record_link_with(
                owner,
                record,
                1,
                record_vector_destruct,
                record_string_release,
            );
        }
        assert_eq!(fix.record[3], 0xbbbb, "link word chains the old occupant");
        assert_eq!(fix.owner[1], record as usize, "slot receives the record");
        assert_eq!(
            DESTRUCT_ARG.load(Ordering::SeqCst),
            record as usize + RECORD_VECTOR,
            "vector at record + 0x14",
        );
        assert_eq!(
            RELEASE_ARG.load(Ordering::SeqCst),
            record as usize + RECORD_VECTOR + RETURN_BIAS - 4,
            "release argument is the returned vector minus four",
        );
        assert!(
            DESTRUCT_STEP.load(Ordering::SeqCst) < RELEASE_STEP.load(Ordering::SeqCst),
            "vector destruct precedes string release",
        );
    }

    #[test]
    fn any_nonzero_flag_tears_down() {
        for flag in [-1i32, 2, i32::MAX] {
            reset_observations();
            let mut fix = Fixture { owner: [0, 0], record: [0; 7] };
            unsafe {
                cxx_string_vector_record_link_with(
                    fix.owner.as_mut_ptr() as *mut u8,
                    fix.record.as_mut_ptr() as *mut u8,
                    flag,
                    record_vector_destruct,
                    record_string_release,
                );
            }
            assert_ne!(DESTRUCT_ARG.load(Ordering::SeqCst), 0, "flag {flag} destructs");
            assert_ne!(RELEASE_ARG.load(Ordering::SeqCst), 0, "flag {flag} releases");
        }
    }

    #[test]
    fn null_old_occupant_chains_through() {
        reset_observations();
        let mut fix = Fixture { owner: [0, 0], record: [0xdddd; 7] };
        unsafe {
            cxx_string_vector_record_link_with(
                fix.owner.as_mut_ptr() as *mut u8,
                fix.record.as_mut_ptr() as *mut u8,
                0,
                record_vector_destruct,
                record_string_release,
            );
        }
        assert_eq!(fix.record[3], 0, "null old occupant is chained verbatim");
    }
}
