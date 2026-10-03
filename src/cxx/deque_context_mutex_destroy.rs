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
//! Deliberate deviations: the unported deque clear (a loop over pop-front
//! 0x083df194 until container_is_empty 0x083d7600) remains a fixed-address ARM
//! call. Hosts require an explicit injected implementation, never an inert
//! fallback. Context and mutex destruction reuse their existing Rust ports.

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DequeContextMutexDestroyOps {
    pub clear_deque: unsafe extern "C" fn(*mut u8) -> *mut u8,
}

#[cfg(not(target_os = "none"))]
pub static mut DEQUE_CONTEXT_MUTEX_DESTROY_OPS: Option<DequeContextMutexDestroyOps> = None;

#[inline(always)]
unsafe fn clear_deque(deque: *mut u8) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let clear: unsafe extern "C" fn(*mut u8) -> *mut u8 =
            core::mem::transmute(0x083d_f2d4usize);
        clear(deque)
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_CONTEXT_MUTEX_DESTROY_OPS))
            .expect("retail deque clear requires a host implementation");
        (ops.clear_deque)(deque)
    }
}

/// Clear the embedded deque, destroy context, then destroy mutex and return this.
///
/// # Safety
/// `this` must satisfy the retail deque (+0x38), opaque-context (+0x1c), and
/// mutex contracts. Byte offsets are target offsets, independent of host pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn destroy_deque_context_and_mutex(this: *mut u8) -> *mut u8 {
    let deque = clear_deque(this.wrapping_add(0x38));
    let context = super::opaque_context_destroy::destroy_opaque_context(
        deque.wrapping_sub(0x1c).cast());
    super::mutex_destroy::cxx_mutex_destroy(context.cast::<u8>().wrapping_sub(0x1c))
}

#[cfg(test)]
mod tests {
    use super::*;

    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut RESULT: *mut u8 = core::ptr::null_mut();

    // Model the count side effect at the retail deque's word 8, not a host
    // BlockDeque byte offset. Returning another object detects lost r0 chaining.
    unsafe extern "C" fn clear_model(deque: *mut u8) -> *mut u8 {
        deque.cast::<u32>().add(8).write(0);
        RESULT
    }

    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { DEQUE_CONTEXT_MUTEX_DESTROY_OPS = None; }
        }
    }

    #[test]
    fn busy_mutex_does_not_prevent_deque_clear_or_change_return_value() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        let mut object = [0u32; 32];
        object[0] = 0x4d55_5458;
        object[1] = 7; // pthread destroy returns EBUSY after deque cleanup.
        object[(0x38 + 0x20) / 4] = 3;
        let this = object.as_mut_ptr().cast::<u8>();
        unsafe {
            RESULT = this.add(0x38);
            DEQUE_CONTEXT_MUTEX_DESTROY_OPS = Some(DequeContextMutexDestroyOps { clear_deque: clear_model });
            assert_eq!(destroy_deque_context_and_mutex(this), this);
        }
        assert_eq!(object[(0x38 + 0x20) / 4], 0);
        assert_eq!(object[0], 0x4d55_5458);
        assert_eq!(object[1], 7);
    }

    #[test]
    fn adjusted_return_selects_other_object_even_when_mutex_is_invalid() {
        let _lock = LOCK.lock();
        let _restore = Restore;
        let mut source = [0u32; 32];
        let mut destination = [0u32; 32];
        source[(0x38 + 0x20) / 4] = 1;
        destination[0] = 0xdead_beef; // EINVAL, discarded by the C++ wrapper.
        let this = source.as_mut_ptr().cast::<u8>();
        let other = destination.as_mut_ptr().cast::<u8>();
        unsafe {
            RESULT = other.add(0x38);
            DEQUE_CONTEXT_MUTEX_DESTROY_OPS = Some(DequeContextMutexDestroyOps { clear_deque: clear_model });
            assert_eq!(destroy_deque_context_and_mutex(this), other);
        }
        assert_eq!(source[(0x38 + 0x20) / 4], 0);
        assert_eq!(destination[0], 0xdead_beef);
    }
}
