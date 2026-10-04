//! Executes a pointer-slot owner's read request.
//!
//! `FUN_081eefec` @ `0x081eefec`: 68 bytes, [0x081eefec,0x081ef030).
//! Raw A32 decoding finds two inbound plain BLs (0x081eeaa0, 0x081eeadc),
//! four outbound plain BLs, and zero predicated BLs in either direction.
//! Resolve the slot handle, maintain the destination cache range, translate
//! the destination, read into it, and store the returned status at +0x28.
//! The read body owns the transferred count at +0x2c, even on errors.
//! Deliberate deviations: volatile fields preserve reloads across callbacks;
//! host cache maintenance uses a replaceable boundary instead of CP15 hardware.
//! Target maintenance calls verified retail entry 0x080d9b74 (clean/invalidate
//! lines in the 0x180 segment, or the whole cache for lengths >= 0x2800).

use super::slot_array_owner_get::{slot_array_owner_get, SlotArrayOwner};
use super::slot_array_owner_write_request::OwnerWriteRequest;
use crate::drivers::cache_address_translate::cache_address_translate;
use crate::fs::file_read::retail_file_read;

type MaintainRange = unsafe extern "C" fn(u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_maintenance(_destination: u32, _length: u32) {
    panic!("install owner-read cache-maintenance host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_READ_MAINTAIN_RANGE: MaintainRange = missing_maintenance;

/// # Safety
/// Owner and request slot must be readable; the request must be writable.
/// Its target-width destination and selected handle must satisfy the retail
/// read body's contracts. No null, length, or slot-validity guards are added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn slot_array_owner_read_request(
    owner: *const SlotArrayOwner,
    request_slot: *const *mut OwnerWriteRequest,
) {
    let request = request_slot.read_volatile();
    let handle = slot_array_owner_get(owner, core::ptr::addr_of!((*request).slot_index).read_volatile());
    #[cfg(target_os = "none")]
    let maintain: MaintainRange = core::mem::transmute(0x080d_9b74usize);
    #[cfg(not(target_os = "none"))]
    let maintain = core::ptr::addr_of!(OWNER_READ_MAINTAIN_RANGE).read_volatile();
    maintain(core::ptr::addr_of!((*request).source).read_volatile(),
        core::ptr::addr_of!((*request).length).read_volatile());
    let destination = cache_address_translate(core::ptr::addr_of!((*request).source).read_volatile());
    let status = retail_file_read(handle as usize as *mut core::ffi::c_void,
        core::ptr::addr_of!((*request).length).read_volatile(),
        destination as usize as *mut u8, core::ptr::addr_of_mut!((*request).written));
    core::ptr::addr_of_mut!((*request).status).write_volatile(status as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::file_read::RETAIL_FILE_READ_BODY;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};

    static mut REQUEST: *mut OwnerWriteRequest = core::ptr::null_mut();
    static mut SLOT: *mut *mut OwnerWriteRequest = core::ptr::null_mut();
    static mut RESULT: i32 = 0;
    static mut PHASE: u32 = 0;

    unsafe extern "C" fn maintain(destination: u32, length: u32) {
        assert_eq!((destination, length), (0x1800_0040, 13));
        assert_eq!(PHASE, 0);
        PHASE = 1;
        // Reentrant slot replacement must not redirect the cached request.
        SLOT.write(core::ptr::null_mut());
        (*REQUEST).source = 0x1800_0080;
        (*REQUEST).length = 0;
    }
    unsafe extern "C" fn read(handle: *mut core::ffi::c_void, count: u32,
        destination: *mut u8, transferred: *mut u32, control: u32) -> i32 {
        assert_eq!(PHASE, 1);
        PHASE = 2;
        assert!(handle.is_null()); // Negative/out-of-range index still reads.
        assert_eq!((count, destination as usize, control), (0, 0x2200_0080, 0));
        assert_eq!((*REQUEST).status, 88);
        assert_eq!(transferred, core::ptr::addr_of_mut!((*REQUEST).written));
        transferred.write(7); // Partial progress survives an error status.
        RESULT
    }

    #[test]
    fn reloads_after_maintenance_and_preserves_partial_progress_on_error() {
        let _guard = crate::ft::system::TEST_OPS_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SLOT_ARRAY_OWNER_READ_REQUEST, 4096) else {
            assert!(note_missing_u32_fixture("cxx/slot_array_owner_read_request"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(slab, 0, 4096);
            let owner = SlotArrayOwner { opaque_00: 0, opaque_04: 0, opaque_08: 0, slots: slab as u32 };
            let old_maintain = OWNER_READ_MAINTAIN_RANGE;
            let old_read = RETAIL_FILE_READ_BODY;
            OWNER_READ_MAINTAIN_RANGE = maintain;
            RETAIL_FILE_READ_BODY = read;
            for (index, status) in [(-1, -7), (0, 0), (i32::MAX, 2)] {
                let mut request = OwnerWriteRequest { opaque_00_to_10: [0; 5], observer: 0,
                    opaque_18_to_1c: [0; 2], source: 0x1800_0040, length: 13,
                    status: 88, written: 77, file_length: 66, slot_index: index };
                let mut slot = &mut request as *mut OwnerWriteRequest;
                REQUEST = slot; SLOT = &mut slot; RESULT = status; PHASE = 0;
                slot_array_owner_read_request(&owner, &slot);
                assert_eq!((request.status, request.written, request.file_length), (status as u32, 7, 66));
                assert!(slot.is_null());
                assert_eq!(PHASE, 2);
            }
            OWNER_READ_MAINTAIN_RANGE = old_maintain;
            RETAIL_FILE_READ_BODY = old_read;
            REQUEST = core::ptr::null_mut(); SLOT = core::ptr::null_mut();
        }
    }
}
