//! **0x083d58ac** (44 bytes; two verified inbound plain `bl` sites and one
//! predicated `blne` call).
//!
//! Raw `osos.dec` establishes the exact extent 0x083d58ac..0x083d58d8; the
//! vtable literal at 0x083d58d8 begins the separately entered function at
//! 0x083d58dc. The two inbound plain calls are at 0x083b46ac and 0x083b476c.
//!
//! # Algorithm
//!
//! Stores vtable 0x089a6690 at `this+0x00`, releases the owned allocation at
//! `this+0x14` when non-null, clears that word, and returns `this`.
//!
//! Target fields are addressed as `u32` words, preserving the ARM `+0x14`
//! offset on 64-bit hosts. Deliberate deviations: an internal noinline wrapper
//! retains a direct Rust `bl` target for the already-ported `free`; Rust does
//! not preserve the retail register allocation or predicated branch instruction.

const VTABLE_WORD: u32 = 0x089a_6690;
const OWNED_PAYLOAD_WORD: usize = 0x14 / 4;

#[inline(never)]
unsafe extern "C" fn release_owned_payload(payload: *mut u8) {
    unsafe { crate::runtime::malloc_rt::free(payload) };
}

#[cfg(test)]
#[inline(always)]
unsafe fn vtable_owned_payload_destruct_with(
    this: *mut u32,
    release: unsafe extern "C" fn(*mut u8),
) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let payload = this.add(OWNED_PAYLOAD_WORD).read_volatile() as *mut u8;
        if !payload.is_null() {
            release(payload);
        }
        this.add(OWNED_PAYLOAD_WORD).write_volatile(0);
    }
    this
}

/// Destroys the owned allocation of an opaque vtable-backed subobject.
///
/// # Safety
///
/// `this` must point to writable target-layout storage through `+0x14`; a
/// nonzero word at `+0x14` must be valid for [`crate::runtime::malloc_rt::free`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_owned_payload_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let payload = this.add(OWNED_PAYLOAD_WORD).read_volatile() as *mut u8;
        if !payload.is_null() {
            release_owned_payload(payload);
        }
        this.add(OWNED_PAYLOAD_WORD).write_volatile(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_PAYLOAD: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_release(payload: *mut u8) {
        RELEASE_CALLS.fetch_add(1, Ordering::SeqCst);
        RELEASED_PAYLOAD.store(payload as usize, Ordering::SeqCst);
    }

    #[test]
    fn installs_vtable_releases_payload_and_clears_owner() {
        let _lock = LOCK.lock();
        let mut object = [0xfeed_face; OWNED_PAYLOAD_WORD + 2];
        let payload = 0x1234_5000usize as *mut u8;
        object[OWNED_PAYLOAD_WORD] = payload as u32;
        RELEASE_CALLS.store(0, Ordering::SeqCst);
        RELEASED_PAYLOAD.store(0, Ordering::SeqCst);

        let result = unsafe {
            vtable_owned_payload_destruct_with(object.as_mut_ptr(), record_release)
        };

        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(object[OWNED_PAYLOAD_WORD], 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_PAYLOAD.load(Ordering::SeqCst), payload as usize);
        assert_eq!(object[1], 0xfeed_face, "intermediate field remains intact");
        assert_eq!(object[OWNED_PAYLOAD_WORD + 1], 0xfeed_face, "suffix guard");
    }

    #[test]
    fn null_payload_skips_release_and_is_still_cleared() {
        let _lock = LOCK.lock();
        let mut object = [0xfeed_face; OWNED_PAYLOAD_WORD + 1];
        object[OWNED_PAYLOAD_WORD] = 0;
        RELEASE_CALLS.store(0, Ordering::SeqCst);

        let result = unsafe {
            vtable_owned_payload_destruct_with(object.as_mut_ptr(), record_release)
        };

        assert_eq!(result, object.as_mut_ptr());
        assert_eq!(object[0], VTABLE_WORD);
        assert_eq!(object[OWNED_PAYLOAD_WORD], 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 0);
    }
}
