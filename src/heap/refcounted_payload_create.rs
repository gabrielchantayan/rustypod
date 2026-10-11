//! Creates a payload handle and initializes its reference count and BE marker.
//!
//! Original: FUN_0805a10c @ 0x0805a10c. True extent 64 bytes through
//! 0x0805a14b: 60 instruction bytes plus the 0xffff8000 literal; the next
//! independent function starts at 0x0805a14c. Raw A32 decoding verifies two
//! incoming plain BLs (0x08044658, 0x080e1e2c), no predicated incoming BLs,
//! one outgoing plain BL to 0x0805b668 and one BLNE to 0x0809c7ec.
//! Call the resident 32-byte payload-handle allocator. Preserve its status;
//! only on success with a non-NULL resulting handle, set payload+0x18 to
//! halfword 1 and write BE 0x8000 at payload+8. Ignore the marker writer's
//! status. Deliberate deviations: the unported allocator is an address seam;
//! the marker writer uses its existing Rust port. Single-pointer slot and
//! handle fields widen on hosts, consistently with payload_u16_be_store;
//! ARM retains four-byte pointers. No additional NULL-payload check.
//! Verification: host suite and standalone production-entry smoke pass.
//! ARM match retains the error/null guards, +0x18 halfword store, marker
//! call and saved allocator result. LLVM uses BLX through an address literal
//! instead of the allocator BL, and branches instead of predication.
//! No on-device allocator execution was performed.

use crate::util::payload_u16_be_store::payload_u16_be_store;

pub type PayloadHandleAllocate = unsafe extern "C" fn(*mut *mut u8) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocator(_slot: *mut *mut u8) -> i32 {
    panic!("payload handle allocation requires the resident implementation")
}

#[cfg(not(target_os = "none"))]
pub static mut PAYLOAD_HANDLE_ALLOCATE: PayloadHandleAllocate = missing_allocator;

/// # Safety
/// The slot must satisfy the resident allocator's contract. On successful
/// non-NULL output, its first pointer must address a writable payload through
/// +0x19, with halfword alignment at +0x18.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_payload_create(slot: *mut *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    let allocate: PayloadHandleAllocate = core::mem::transmute(0x0805_b668usize);
    #[cfg(not(target_os = "none"))]
    let allocate = core::ptr::read_volatile(core::ptr::addr_of!(PAYLOAD_HANDLE_ALLOCATE));
    let status = allocate(slot);
    if status == 0 {
        let handle = slot.read().cast::<*mut u8>();
        if !handle.is_null() {
            handle.read().add(0x18).cast::<u16>().write(1);
            payload_u16_be_store(handle, 0xffff_8000);
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut RESULT: i32 = 0;
    static mut OUTPUT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn allocate(slot: *mut *mut u8) -> i32 {
        if !slot.is_null() { slot.write(OUTPUT); }
        RESULT
    }

    struct Reset(PayloadHandleAllocate);
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { PAYLOAD_HANDLE_ALLOCATE = self.0; } }
    }

    #[test]
    fn preserves_allocator_errors_without_touching_output_payload() {
        let _lock = LOCK.lock();
        unsafe {
            let _reset = Reset(PAYLOAD_HANDLE_ALLOCATE);
            PAYLOAD_HANDLE_ALLOCATE = allocate;
            let mut payload = [0xa5a5u16; 16];
            let mut handle = payload.as_mut_ptr().cast::<u8>();
            OUTPUT = core::ptr::addr_of_mut!(handle).cast();
            for status in [-50, -108, i32::MIN, 1] {
                RESULT = status;
                let mut slot = core::ptr::null_mut();
                assert_eq!(refcounted_payload_create(&mut slot), status);
                assert_eq!(payload, [0xa5a5; 16]);
                assert_eq!(refcounted_payload_create(core::ptr::null_mut()), status);
            }
        }
    }

    #[test]
    fn successful_null_handle_skips_dereference() {
        let _lock = LOCK.lock();
        unsafe {
            let _reset = Reset(PAYLOAD_HANDLE_ALLOCATE);
            PAYLOAD_HANDLE_ALLOCATE = allocate;
            RESULT = 0;
            OUTPUT = core::ptr::null_mut();
            let mut slot = 1usize as *mut u8;
            assert_eq!(refcounted_payload_create(&mut slot), 0);
            assert!(slot.is_null());
        }
    }

    #[test]
    fn initializes_only_marker_and_refcount_after_allocation() {
        let _lock = LOCK.lock();
        unsafe {
            let _reset = Reset(PAYLOAD_HANDLE_ALLOCATE);
            PAYLOAD_HANDLE_ALLOCATE = allocate;
            RESULT = 0;
            for old_count in [0, 1, 1000, u16::MAX] {
                let mut payload = [0xa5a5u16; 16];
                payload[12] = old_count;
                let mut handle = payload.as_mut_ptr().cast::<u8>();
                OUTPUT = core::ptr::addr_of_mut!(handle).cast();
                let mut slot = core::ptr::null_mut();
                assert_eq!(refcounted_payload_create(&mut slot), 0);
                let mut expected = [0xa5a5u16; 16];
                expected[4] = u16::from_ne_bytes([0x80, 0]);
                expected[12] = 1;
                assert_eq!(payload, expected);
            }
        }
    }
}
