//! Destructor for the otherwise unidentified vtable `0x089a6720` class.
//!
//! Original: `FUN_083d5c60` @ **0x083d5c60**, **44 instruction bytes**.
//! Raw words end with `pop {r4,pc}` at 0x083d5c88; the vtable literal is
//! at 0x083d5c8c, and the next real function begins at 0x083d5c90.
//! Binary branch decoding verifies one inbound plain BL (0x082845b0), zero
//! inbound predicated BLs, and one outbound BLNE to free @ 0x0802edc8.
//!
//! Installs vtable 0x089a6720, frees the nonzero owned payload at +0x14,
//! clears that word even when already zero, and returns this. The caller
//! at 0x082845a4 guards NULL and then deletes the returned object; this
//! non-deleting destructor itself does not guard NULL.
//!
//! Target fields remain u32 words on hosts. Deliberate codegen deviations:
//! a noinline release wrapper retains a direct BL target for the existing
//! free port; LLVM need not preserve retail register allocation or BLNE.

const VTABLE_WORD: u32 = 0x089a_6720;
const OWNED_PAYLOAD_WORD: usize = 0x14 / 4;

#[inline(never)]
unsafe extern "C" fn release_owned_payload(payload: *mut u8) {
    unsafe { crate::runtime::malloc_rt::free(payload) };
}

/// Destroys the owned payload without freeing the containing object.
///
/// # Safety
/// `this` must reference writable, aligned target-layout storage through
/// +0x14. Its nonzero payload word must be valid for the runtime free port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_089a6720_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let payload = this.add(OWNED_PAYLOAD_WORD).read_volatile() as usize as *mut u8;
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
    use crate::runtime::malloc_rt::{HeapOps, HEAP_OPS};
    use core::sync::atomic::{AtomicUsize, Ordering};

    static OBJECT: AtomicUsize = AtomicUsize::new(0);
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static PAYLOAD: AtomicUsize = AtomicUsize::new(0);
    static VTABLE_AT_FREE: AtomicUsize = AtomicUsize::new(0);
    static OWNER_AT_FREE: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_free(payload: *mut u8) {
        let object = OBJECT.load(Ordering::SeqCst) as *const u32;
        CALLS.fetch_add(1, Ordering::SeqCst);
        PAYLOAD.store(payload as usize, Ordering::SeqCst);
        unsafe {
            VTABLE_AT_FREE.store(object.read() as usize, Ordering::SeqCst);
            OWNER_AT_FREE.store(object.add(OWNED_PAYLOAD_WORD).read() as usize, Ordering::SeqCst);
        }
    }

    struct RestoreHeap(HeapOps);
    impl Drop for RestoreHeap {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(HEAP_OPS).write(self.0) };
        }
    }

    #[test]
    fn payload_release_order_null_and_repeat_preserve_other_words() {
        let _lock = crate::runtime::malloc_rt::tests::lock_ops();
        let saved = unsafe { core::ptr::addr_of!(HEAP_OPS).read() };
        let _restore = RestoreHeap(saved);
        unsafe { core::ptr::addr_of_mut!(HEAP_OPS).write(HeapOps { free: record_free, ..saved }) };

        for payload in [0u32, 0x1234_5000, 0xffff_fffc] {
            let mut object = [0xfeed_face; 7];
            object[OWNED_PAYLOAD_WORD] = payload;
            OBJECT.store(object.as_mut_ptr() as usize, Ordering::SeqCst);
            CALLS.store(0, Ordering::SeqCst);
            PAYLOAD.store(0, Ordering::SeqCst);
            let returned = unsafe { vtable_089a6720_destruct(object.as_mut_ptr()) };
            assert_eq!(returned, object.as_mut_ptr());
            assert_eq!(object, [VTABLE_WORD, 0xfeed_face, 0xfeed_face, 0xfeed_face, 0xfeed_face, 0, 0xfeed_face]);
            assert_eq!(CALLS.load(Ordering::SeqCst), usize::from(payload != 0));
            assert_eq!(PAYLOAD.load(Ordering::SeqCst), payload as usize);
            if payload != 0 {
                assert_eq!(VTABLE_AT_FREE.load(Ordering::SeqCst), VTABLE_WORD as usize);
                assert_eq!(OWNER_AT_FREE.load(Ordering::SeqCst), payload as usize);
            }
            unsafe { vtable_089a6720_destruct(object.as_mut_ptr()) };
            assert_eq!(CALLS.load(Ordering::SeqCst), usize::from(payload != 0), "no double release");
        }
    }
}
