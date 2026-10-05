//! Post a kind-1, zero-payload worker record, FUN_0819c088 @ 0x0819c088.
//! True extent: 48 bytes [0x0819c088, 0x0819c0b8); the next function begins
//! with an independent push. Raw A32 decoding verifies one outbound plain BL
//! (operator_new @ 0x082aadd4), zero predicated BLs, and a tail B to the
//! resident synchronized pointer queue append @ 0x0839e4f8. There are two
//! inbound plain BLs and no predicated inbound BLs.
//!
//! Allocate eight bytes, write record kind 1 and payload 0, then transfer its
//! ownership to the queue embedded at owner+0x28. Ghidra incorrectly inlines
//! the queue append body into this function. Deliberate deviations: reuse the
//! ported allocator; retain the verified resident queue operation on target
//! and injectable host operations. No NULL guard is added. Record fields stay
//! target-width u32 words on hosts; the owner remains opaque byte storage.
//! Codegen review: LLVM reorders the independent field stores and uses a
//! literal-address BX for the resident tail transfer; record values, queue
//! offset and ownership transfer match stock. No device execution performed.

use crate::heap::veneers::operator_new;

#[derive(Clone, Copy)]
pub struct Kind1RecordOps {
    pub allocate: unsafe extern "C" fn(usize) -> *mut u8,
    pub enqueue: unsafe extern "C" fn(*mut u8, *mut u32),
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_enqueue(_: *mut u8, _: *mut u32) {
    panic!("install resident synchronized pointer queue append")
}

#[cfg(not(target_os = "none"))]
pub static mut KIND1_RECORD_OPS: Kind1RecordOps = Kind1RecordOps {
    allocate: operator_new, enqueue: missing_enqueue,
};

/// Allocate and transfer a kind-1 record to the owner's resident queue.
///
/// # Safety
/// `owner+0x28` must be a live resident synchronized pointer queue. Allocation
/// must return eight writable word-aligned bytes; enqueue takes ownership.
/// Host operations must be installed without concurrent mutation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn kind1_record_post(owner: *mut u8) {
    #[cfg(target_os = "none")]
    let ops = Kind1RecordOps {
        allocate: operator_new,
        enqueue: core::mem::transmute(0x0839_e4f8usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(KIND1_RECORD_OPS).read();
    post_record(owner, |size| (ops.allocate)(size),
        |queue, record| (ops.enqueue)(queue, record));
}

unsafe fn post_record(
    owner: *mut u8,
    allocate: impl FnOnce(usize) -> *mut u8,
    enqueue: impl FnOnce(*mut u8, *mut u32),
) {
    let record = allocate(8).cast::<u32>();
    record.write(1);
    record.add(1).write(0);
    enqueue(owner.add(0x28), record);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_allocations_are_initialized_before_ownership_transfer() {
        let mut owner = [0xa5u8; 0x60];
        let owner_ptr = owner.as_mut_ptr();
        // Nonzero recycled storage must not leak a prior kind or payload;
        // adjacent allocator storage and the opaque owner stay untouched.
        for old in [0, 1, 0x8000_0000, u32::MAX] {
            let mut storage = [0xdead_beefu32, old, old, 0xcafe_babe];
            unsafe {
                post_record(owner_ptr,
                    |size| { assert_eq!(size, 8); storage.as_mut_ptr().add(1).cast() },
                    |_, record| {
                        assert_eq!(record.read(), 1);
                        assert_eq!(record.add(1).read(), 0);
                        // The consumer owns the initialized record immediately.
                        record.add(1).write(0x1234_5678);
                    });
            }
            assert_eq!(storage, [0xdead_beef, 1, 0x1234_5678, 0xcafe_babe]);
            assert_eq!(owner, [0xa5; 0x60]);
        }
    }
}
