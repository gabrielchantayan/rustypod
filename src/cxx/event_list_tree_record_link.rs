//! `event_list_tree_record_link` — original: `FUN_083c1648` @ 0x083c1648
//! (64 bytes).
//!
//! Raw ARM establishes the exact extent 0x083c1648..0x083c1688: sixteen words
//! from `stmdb sp!, {r4,r5,r6,lr}` through `ldmia sp!, {r4,r5,r6,pc}`; the next
//! independently linked function begins at 0x083c1688. The body chains the
//! owner's +4 slot into the record's +0xc link word, then, when `teardown` is
//! nonzero, destructs the embedded CxxStringVector at +0x18 and releases the
//! two preceding COW string slots at +0x14 and +0x10. It stores `record` into
//! the owner slot last. Raw-word decoding finds exactly three unconditional
//! `bl` instructions and no predicated calls.
//!
//! # Deliberate deviation
//!
//! None in behavior. LLVM may prove that `cxx_string_vector_destruct` returns
//! its argument and fold the return-relative release addresses to record-relative
//! addresses.

use crate::cxx::string::cxx_string_release;
use crate::cxx::string_vector_destruct::{cxx_string_vector_destruct, CxxStringVector};

type VectorDestruct = unsafe extern "C" fn(*mut CxxStringVector) -> *mut CxxStringVector;
type StringRelease = unsafe extern "C" fn(*mut *mut u8);

const OWNER_SLOT: usize = 1;
const RECORD_LINK: usize = 3;
const RECORD_VECTOR: usize = 0x18;

/// Links `record` into `owner`'s +4 slot. If `teardown` is nonzero, destroys
/// the vector at record +0x18 and releases the COW string slots before it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.event_list_tree_record_link")]
#[inline(never)]
pub unsafe extern "C" fn event_list_tree_record_link(
    owner: *mut u8,
    record: *mut u8,
    teardown: i32,
) {
    unsafe {
        event_list_tree_record_link_with(
            owner,
            record,
            teardown,
            cxx_string_vector_destruct,
            cxx_string_release,
        )
    }
}

#[inline(always)]
unsafe fn event_list_tree_record_link_with(
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
            release_string((vector as *mut u8).sub(8) as *mut *mut u8);
        }
        *(owner as *mut *mut u8).add(OWNER_SLOT) = record;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static DESTRUCT_ARG: AtomicUsize = AtomicUsize::new(0);
    static FIRST_RELEASE_ARG: AtomicUsize = AtomicUsize::new(0);
    static SECOND_RELEASE_ARG: AtomicUsize = AtomicUsize::new(0);
    static STEP: AtomicUsize = AtomicUsize::new(0);
    static DESTRUCT_STEP: AtomicUsize = AtomicUsize::new(0);
    static FIRST_RELEASE_STEP: AtomicUsize = AtomicUsize::new(0);
    static SECOND_RELEASE_STEP: AtomicUsize = AtomicUsize::new(0);
    const RETURN_BIAS: usize = 0x40;

    unsafe extern "C" fn record_vector_destruct(
        vector: *mut CxxStringVector,
    ) -> *mut CxxStringVector {
        DESTRUCT_ARG.store(vector as usize, Ordering::SeqCst);
        DESTRUCT_STEP.store(STEP.fetch_add(1, Ordering::SeqCst), Ordering::SeqCst);
        (vector as *mut u8).add(RETURN_BIAS) as *mut CxxStringVector
    }

    unsafe extern "C" fn record_string_release(slot: *mut *mut u8) {
        let step = STEP.fetch_add(1, Ordering::SeqCst);
        if FIRST_RELEASE_ARG
            .compare_exchange(0, slot as usize, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            FIRST_RELEASE_STEP.store(step, Ordering::SeqCst);
        } else {
            SECOND_RELEASE_ARG.store(slot as usize, Ordering::SeqCst);
            SECOND_RELEASE_STEP.store(step, Ordering::SeqCst);
        }
    }

    fn reset_observations() {
        DESTRUCT_ARG.store(0, Ordering::SeqCst);
        FIRST_RELEASE_ARG.store(0, Ordering::SeqCst);
        SECOND_RELEASE_ARG.store(0, Ordering::SeqCst);
        DESTRUCT_STEP.store(usize::MAX, Ordering::SeqCst);
        FIRST_RELEASE_STEP.store(usize::MAX, Ordering::SeqCst);
        SECOND_RELEASE_STEP.store(usize::MAX, Ordering::SeqCst);
        STEP.store(0, Ordering::SeqCst);
    }

    struct Fixture {
        owner: [usize; 2],
        record: [usize; 7],
    }

    #[test]
    fn zero_flag_links_without_teardown() {
        reset_observations();
        let mut fix = Fixture { owner: [0, 0xaaaa], record: [0; 7] };
        unsafe {
            event_list_tree_record_link_with(
                fix.owner.as_mut_ptr() as *mut u8,
                fix.record.as_mut_ptr() as *mut u8,
                0,
                record_vector_destruct,
                record_string_release,
            );
        }
        assert_eq!(fix.record[3], 0xaaaa);
        assert_eq!(fix.owner[1], fix.record.as_ptr() as usize);
        assert_eq!(DESTRUCT_ARG.load(Ordering::SeqCst), 0);
        assert_eq!(FIRST_RELEASE_ARG.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn nonzero_flag_tears_down_in_arm_order() {
        reset_observations();
        let mut fix = Fixture { owner: [0, 0xbbbb], record: [0; 7] };
        let record = fix.record.as_mut_ptr() as *mut u8;
        unsafe {
            event_list_tree_record_link_with(
                fix.owner.as_mut_ptr() as *mut u8,
                record,
                -1,
                record_vector_destruct,
                record_string_release,
            );
        }
        let returned_vector = record as usize + RECORD_VECTOR + RETURN_BIAS;
        assert_eq!(fix.record[3], 0xbbbb);
        assert_eq!(fix.owner[1], record as usize);
        assert_eq!(DESTRUCT_ARG.load(Ordering::SeqCst), record as usize + RECORD_VECTOR);
        assert_eq!(FIRST_RELEASE_ARG.load(Ordering::SeqCst), returned_vector - 4);
        assert_eq!(SECOND_RELEASE_ARG.load(Ordering::SeqCst), returned_vector - 8);
        assert!(DESTRUCT_STEP.load(Ordering::SeqCst) < FIRST_RELEASE_STEP.load(Ordering::SeqCst));
        assert!(FIRST_RELEASE_STEP.load(Ordering::SeqCst) < SECOND_RELEASE_STEP.load(Ordering::SeqCst));
    }
}
