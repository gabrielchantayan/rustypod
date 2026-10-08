//! Conditional release of an owner's heap-backed buffer.

/// owner_buffer_release — original: FUN_081368a0 @ 0x081368a0.
/// True extent: 28 bytes, ending at 0x081368bc's independent push prologue.
/// Raw whole-image decoding verifies two inbound plain BLs (0x0813695c,
/// 0x08136f60), zero predicated inbound BLs, and one outbound BLNE to free
/// @ 0x0802edc8. If the ownership word at +0xe8 is nonzero, free the target
/// pointer at +0x9c; otherwise do not read that pointer. Return zero without
/// clearing either word. The reset caller subsequently installs the inline
/// buffer at +0xa0 and clears ownership itself.
///
/// Deliberate deviation: call the existing Rust free port, whose documented
/// heap-ops dispatch replaces the retail direct call. Fields remain u32 words
/// on hosts, preserving the target's four-byte layout.
///
/// # Safety
/// `owner` must name an aligned readable record through +0xeb. When ownership
/// is nonzero, the +0x9c word must be NULL or a live allocation accepted by
/// the ADS free port. Repeating release without resetting ownership can
/// double-free, exactly as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owner_buffer_release(owner: *const u32) -> u32 {
    if owner.add(0xe8 / 4).read() != 0 {
        crate::runtime::malloc_rt::free(owner.add(0x9c / 4).read() as usize as *mut u8);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::runtime::malloc_rt::{HeapOps, HEAP_OPS};
    use core::ptr;
    use std::vec::Vec;
    use parking_lot::Mutex;

    static RELEASED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    unsafe extern "C" fn record_free(block: *mut u8) {
        RELEASED.lock().push(block as usize);
    }

    struct Restore(HeapOps);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ptr::addr_of_mut!(HEAP_OPS).write_volatile(self.0); }
        }
    }

    #[test]
    fn ownership_controls_release_without_changing_the_owner() {
        let _lock = crate::runtime::malloc_rt::tests::lock_ops();
        unsafe {
            let saved = ptr::addr_of!(HEAP_OPS).read_volatile();
            let _restore = Restore(saved);
            ptr::addr_of_mut!(HEAP_OPS).write_volatile(HeapOps { free: record_free, ..saved });
            for (ownership, buffer, expected) in [
                (0, 0xdead_beef, None),
                (1, 0, None),
                (1, 0x1234_5678, Some(0x1234_5678usize)),
                (u32::MAX, 0x8765_4320, Some(0x8765_4320usize)),
            ] {
                let mut owner = [0xa5a5_a5a5u32; 0xec / 4];
                owner[0x9c / 4] = buffer;
                owner[0xe8 / 4] = ownership;
                let before = owner;
                RELEASED.lock().clear();
                assert_eq!(owner_buffer_release(owner.as_ptr()), 0);
                assert_eq!(owner, before);
                assert_eq!(*RELEASED.lock(), expected.into_iter().collect::<Vec<_>>());
            }
        }
    }
}
