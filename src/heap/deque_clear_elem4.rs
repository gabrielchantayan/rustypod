//! Clear a four-byte-element deque — retailOS `FUN_083df2d4` @ 0x083df2d4.
//! True size: 44 bytes, ending at 0x083df300's independent push prologue.
//! Whole-image raw A32 decoding verifies one inbound plain BL (0x08261c30),
//! no predicated BLs or inbound B; two outbound plain BLs, no predicated BLs.
//!
//! Check count at word 8 with container_is_empty; while nonzero, pop front
//! through 0x083df194, then recheck. Return the original deque, ignoring the
//! pop helper's r0. Empty deques are untouched; no element destructor is called.
//! Deliberate deviations: reuse the equivalent Rust empty predicate. Pop-front
//! remains a verified retail-address seam (advances cur by four, decrements
//! count, releases exhausted blocks and finally the map). Hosts inject that
//! operation explicitly. Raw target words keep count at +0x20 on every host.

#[cfg(not(target_os = "none"))]
pub static mut DEQUE_POP_FRONT_ELEM4: Option<unsafe extern "C" fn(*mut u8)> = None;

#[cfg(test)]
pub(crate) static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[inline(always)]
unsafe fn pop_front(deque: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let pop: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x083d_f194usize);
        pop(deque);
    }
    #[cfg(not(target_os = "none"))]
    {
        let pop = core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_POP_FRONT_ELEM4))
            .expect("retail deque pop-front requires a host implementation");
        pop(deque);
    }
}

/// # Safety
/// `deque` must be a valid retail four-byte deque, including any backing blocks
/// and map required by pop-front. Hosts must install a faithful pop operation
/// before clearing a nonempty deque and serialize replacement of the seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_clear_elem4(deque: *mut u8) -> *mut u8 {
    while crate::cxx::templates::container_is_empty(deque) == 0 {
        pop_front(deque);
    }
    deque
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn pop_model(deque: *mut u8) {
        let words = deque.cast::<u32>();
        let count = words.add(8).read();
        assert_ne!(count, 0, "never pop an empty deque");
        words.write(words.read().wrapping_add(4));
        words.add(8).write(count - 1);
        if count == 1 { words.add(9).write(0); }
    }

    #[test]
    fn empty_does_not_require_pop_or_touch_storage() {
        let _lock = TEST_LOCK.lock();
        unsafe { DEQUE_POP_FRONT_ELEM4 = None; }
        let mut words = [0xdead_beefu32; 11];
        words[8] = 0;
        let before = words;
        let deque = words.as_mut_ptr().cast();
        unsafe { assert_eq!(deque_clear_elem4(deque), deque); }
        assert_eq!(words, before);
    }

    #[test]
    fn clears_single_and_multiple_elements_and_preserves_identity() {
        let _lock = TEST_LOCK.lock();
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { DEQUE_POP_FRONT_ELEM4 = None; } }
        }
        let _restore = Restore;
        unsafe { DEQUE_POP_FRONT_ELEM4 = Some(pop_model); }
        for count in [1, 2, 64, 257] {
            let mut words = [0x1234_5678u32; 11];
            words[8] = count;
            let deque = words.as_mut_ptr().cast();
            unsafe { assert_eq!(deque_clear_elem4(deque), deque); }
            assert_eq!(words[0], 0x1234_5678 + 4 * count);
            assert_eq!(words[8], 0);
            assert_eq!(words[9], 0);
            assert_eq!(&words[1..8], &[0x1234_5678; 7]);
            assert_eq!(words[10], 0x1234_5678);
            let cleared = words;
            unsafe { assert_eq!(deque_clear_elem4(deque), deque); }
            assert_eq!(words, cleared);
        }
    }
}
