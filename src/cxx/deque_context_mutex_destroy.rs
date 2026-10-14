//! `destroy_deque_context_and_mutex` — retailOS `FUN_08261c28` @ 0x08261c28.
//! True extent: 32 bytes, 0x08261c28..0x08261c48, ending in a tail branch;
//! the next independent push {r3,r4,r5,lr} pins the boundary. Raw A32 decoding
//! finds two inbound plain BLs (0x08261cbc, 0x08261cc4), zero predicated BLs
//! and no inbound B. The body has two plain BLs and one tail B, no predicates.
//!
//! Clear the four-byte-element deque at this + 0x38 through 0x083df2d4,
//! subtract 0x1c from its returned pointer, destroy the opaque context through
//! 0x08262944, subtract another 0x1c, then tail-call cxx_mutex_destroy at
//! 0x08261e54. Both verified callees return their input; retain the return-value
//! chain rather than assuming that when adjusting pointers. No NULL guard.
//!
//! Deliberate deviations: deque clearing, context destruction and mutex
//! destruction reuse their Rust ports. The deque's pop-front operation remains
//! a verified retail-address seam with an explicit host implementation.

/// Clear the embedded deque, destroy context, then destroy mutex and return this.
///
/// # Safety
/// `this` must satisfy the retail deque (+0x38), opaque-context (+0x1c), and
/// mutex contracts. Byte offsets are target offsets, independent of host pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destroy_deque_context_and_mutex(this: *mut u8) -> *mut u8 {
    let deque = crate::heap::deque_clear_elem4::deque_clear_elem4(this.wrapping_add(0x38));
    let context = super::opaque_context_destroy::destroy_opaque_context(
        deque.wrapping_sub(0x1c).cast());
    super::mutex_destroy::cxx_mutex_destroy(context.cast::<u8>().wrapping_sub(0x1c))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::heap::deque_clear_elem4::{DEQUE_POP_FRONT_ELEM4, TEST_LOCK};

    unsafe extern "C" fn pop_model(deque: *mut u8) {
        let count = deque.cast::<u32>().add(8);
        count.write(count.read() - 1);
    }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { DEQUE_POP_FRONT_ELEM4 = None; }
        }
    }

    #[test]
    fn busy_mutex_does_not_prevent_deque_clear_or_change_return_value() {
        let _lock = TEST_LOCK.lock();
        let _restore = Restore;
        let mut object = [0u32; 32];
        object[0] = 0x4d55_5458;
        object[1] = 7; // pthread destroy returns EBUSY after deque cleanup.
        object[(0x38 + 0x20) / 4] = 3;
        let this = object.as_mut_ptr().cast::<u8>();
        unsafe {
            DEQUE_POP_FRONT_ELEM4 = Some(pop_model);
            assert_eq!(destroy_deque_context_and_mutex(this), this);
        }
        assert_eq!(object[(0x38 + 0x20) / 4], 0);
        assert_eq!(object[0], 0x4d55_5458);
        assert_eq!(object[1], 7);
    }

}
