//! Clear a path-record deque — retailOS `FUN_083de1b0` @ 0x083de1b0.
//! True size: 44 bytes, ending at the independent push at 0x083de1dc.
//! Whole-image aligned raw A32 scan: one inbound plain BL (0x081efa50),
//! zero predicated inbound BL; two outbound plain BL, zero predicated BL.
//!
//! Check the count at word 8 before each pop. While nonempty, call the
//! path-record pop-front operation at 0x083de03c, then recheck. Return the
//! original deque. Pop destroys the record's owned string and retires blocks
//! and the map as necessary; this wrapper must not duplicate that cleanup.
//! Deliberate deviations: reuse the equivalent Rust container_is_empty;
//! the unported pop remains a fixed-address device boundary with an explicit
//! host implementation slot. Target-width words preserve count at +0x20.

#[cfg(not(target_os = "none"))]
pub static mut DEQUE_POP_FRONT_ELEM12: Option<unsafe extern "C" fn(*mut u8)> = None;

#[inline(always)]
unsafe fn pop_front(deque: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let pop: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x083d_e03cusize);
        pop(deque);
    }
    #[cfg(not(target_os = "none"))]
    {
        let pop = core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_POP_FRONT_ELEM12))
            .expect("retail path-record pop requires a host implementation");
        pop(deque);
    }
}

/// # Safety
/// `deque` must be aligned for u32 and point to a valid retail path-record
/// deque, including all backing blocks, map, and owned records needed by pop.
/// Hosts must install a pop implementation before clearing a nonempty deque
/// and serialize replacement of the host slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn deque_clear_elem12(deque: *mut u8) -> *mut u8 {
    while crate::cxx::templates::container_is_empty(deque) == 0 {
        pop_front(deque);
    }
    deque
}

#[cfg(test)]
mod tests {
    use super::*;

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn pop_model(deque: *mut u8) {
        let words = deque.cast::<u32>();
        let count = words.add(8).read();
        assert_ne!(count, 0, "empty deques must never be popped");
        words.write(words.read().wrapping_add(12));
        words.add(8).write(count - 1);
        if count == 1 { words.add(9).write(0); }
    }

    #[test]
    fn empty_preserves_every_word_without_a_pop_implementation() {
        let _lock = LOCK.lock();
        unsafe { DEQUE_POP_FRONT_ELEM12 = None; }
        let mut words = [0xdead_beefu32; 11];
        words[8] = 0;
        let before = words;
        let deque = words.as_mut_ptr().cast();
        unsafe { assert_eq!(deque_clear_elem12(deque), deque); }
        assert_eq!(words, before);
    }

    #[test]
    fn drains_single_multiple_and_wrapping_cursors_then_is_idempotent() {
        let _lock = LOCK.lock();
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) { unsafe { DEQUE_POP_FRONT_ELEM12 = None; } }
        }
        let _restore = Restore;
        unsafe { DEQUE_POP_FRONT_ELEM12 = Some(pop_model); }
        for count in [1u32, 2, 64, 257] {
            let mut words = [0x1234_5678u32; 11];
            words[0] = 0xffff_fff8;
            words[8] = count;
            let deque = words.as_mut_ptr().cast();
            unsafe { assert_eq!(deque_clear_elem12(deque), deque); }
            assert_eq!(words[0], 0xffff_fff8u32.wrapping_add(12 * count));
            assert_eq!(words[8], 0);
            assert_eq!(words[9], 0);
            assert_eq!(&words[1..8], &[0x1234_5678; 7]);
            assert_eq!(words[10], 0x1234_5678);
            let cleared = words;
            unsafe { assert_eq!(deque_clear_elem12(deque), deque); }
            assert_eq!(words, cleared);
        }
    }
}
