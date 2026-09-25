//! Opaque owned-allocation release — retailOS `FUN_083e75ac` at load address
//! `0x083e75ac` (36 bytes, `0x083e75ac..0x083e75cf`). Raw `osos.dec` shows
//! the next independently linked function starts at `0x083e75d0`.
//!
//! ```text
//! 083e75ac  push  {r4, lr}
//! 083e75b0  mov   r4, r0
//! 083e75b4  ldr   r0, [r0]
//! 083e75b8  cmp   r0, #0
//! 083e75bc  beq   0x083e75c8
//! 083e75c0  bl    0x08291fb4
//! 083e75c4  bl    0x082aad24
//! 083e75c8  mov   r0, r4
//! 083e75cc  pop   {r4, pc}
//! ```
//!
//! ## Call sites and algorithm
//!
//! Raw ARM decoding finds two direct inbound `bl` calls and no predicated
//! direct calls. The holder's word zero is an owned [`StringObject`]. When
//! non-NULL, the routine calls the ported
//! [`string_object_opaque_base_destroy`], passes its return to the ported
//! tag-2 [`operator_delete`](crate::heap::veneers::operator_delete), and
//! returns the holder unchanged. The field is deliberately not cleared.
//!
//! Deliberate deviation: Rust expresses the two direct calls normally rather
//! than preserving their ARM scheduling. The host-only helper accepts callees
//! explicitly so its edge cases do not require heap-backed fixture addresses.

use crate::cxx::string_object::StringObject;
use crate::cxx::string_object_opaque_base_destroy::string_object_opaque_base_destroy;
use crate::heap::veneers::operator_delete;

type StringObjectDestroy = unsafe extern "C" fn(*mut StringObject) -> *mut StringObject;
type AllocationDelete = unsafe extern "C" fn(*mut u8);

#[inline(always)]
unsafe fn opaque_owned_allocation_release_with(
    holder: *mut *mut StringObject,
    destroy: StringObjectDestroy,
    delete: AllocationDelete,
) -> *mut *mut StringObject {
    let allocation = holder.read();
    if !allocation.is_null() {
        delete(destroy(allocation).cast());
    }
    holder
}

/// Releases the owned `StringObject` in `holder[0]`, retaining the holder and
/// its stored word exactly as the retailOS routine does.
///
/// Original: `FUN_083e75ac` at `0x083e75ac` (36 bytes; 2 direct `bl` calls,
/// 0 predicated direct calls).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_owned_allocation_release(
    holder: *mut *mut StringObject,
) -> *mut *mut StringObject {
    opaque_owned_allocation_release_with(holder, string_object_opaque_base_destroy, operator_delete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    use core::sync::atomic::{AtomicUsize, Ordering};
    static TEST_LOCK: Mutex<()> = Mutex::new(());


    static DESTROYED: AtomicUsize = AtomicUsize::new(0);
    static DELETED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn destroy_to_adjusted_allocation(
        allocation: *mut StringObject,
    ) -> *mut StringObject {
        DESTROYED.store(allocation as usize, Ordering::Relaxed);
        allocation.cast::<u8>().add(8).cast()
    }

    unsafe extern "C" fn record_delete(allocation: *mut u8) {
        DELETED.store(allocation as usize, Ordering::Relaxed);
    }

    #[test]
    fn null_allocation_skips_both_operations_and_preserves_holder() {
        let _guard = TEST_LOCK.lock();

        let mut allocation = core::ptr::null_mut();
        DESTROYED.store(0, Ordering::Relaxed);
        DELETED.store(0, Ordering::Relaxed);
        unsafe {
            assert_eq!(
                opaque_owned_allocation_release_with(
                    &mut allocation,
                    destroy_to_adjusted_allocation,
                    record_delete,
                ),
                core::ptr::addr_of_mut!(allocation),
            );
        }
        assert_eq!(DESTROYED.load(Ordering::Relaxed), 0);
        assert_eq!(DELETED.load(Ordering::Relaxed), 0);
        assert!(allocation.is_null());
    }

    #[test]
    fn destroys_then_deletes_the_destroyer_result_without_clearing_field() {
        let _guard = TEST_LOCK.lock();

        let mut storage = [0u8; 16];
        let mut allocation = storage.as_mut_ptr().cast::<StringObject>();
        DESTROYED.store(0, Ordering::Relaxed);
        DELETED.store(0, Ordering::Relaxed);
        unsafe {
            assert_eq!(
                opaque_owned_allocation_release_with(
                    &mut allocation,
                    destroy_to_adjusted_allocation,
                    record_delete,
                ),
                core::ptr::addr_of_mut!(allocation),
            );
        }
        assert_eq!(DESTROYED.load(Ordering::Relaxed), storage.as_mut_ptr() as usize);
        assert_eq!(DELETED.load(Ordering::Relaxed), unsafe { storage.as_mut_ptr().add(8) } as usize);
        assert_eq!(allocation, storage.as_mut_ptr().cast::<StringObject>());
    }
}
