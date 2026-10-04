//! Executes a pointer-slot owner's close request.
//!
//! `FUN_081ef088` @ `0x081ef088`: true extent [0x081ef088,0x081ef0a4),
//! 28 bytes; the next independent function starts with push at 0x081ef0a4.
//! Whole-image A32 decoding finds two inbound plain BLs (0x081eea90,
//! 0x081eeb08), no predicated BLs; one outbound plain BL at 0x081ef094
//! to 0x081ef3a0, no outbound predicated BLs.
//!
//! Cache the request pointer, release its signed slot index through the owner,
//! then unconditionally clear the original request's status. The retail callee
//! brackets slot_array_remove_at_release with owner+0x14 lock operations;
//! retain that entire operation as a typed fixed-address device boundary.
//! Deliberate deviations: volatile field accesses preserve ordering across the
//! boundary; native pointer-slot width permits host fixtures. Host callbacks
//! replace only the unavailable retail owner-release operation, not this body.

use super::slot_array_owner_get::SlotArrayOwner;
use super::slot_array_owner_write_request::OwnerWriteRequest;

type OwnerRelease = unsafe extern "C" fn(*const SlotArrayOwner, i32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release(_owner: *const SlotArrayOwner, _index: i32) {
    panic!("install owner-close release host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_CLOSE_RELEASE: OwnerRelease = missing_release;

/// # Safety
/// The slot must contain a readable/writable request. Owner must satisfy the
/// retail release operation's contract, including its lock at target +0x14.
/// The original request must remain alive throughout release.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn slot_array_owner_close_request(
    owner: *const SlotArrayOwner,
    request_slot: *const *mut OwnerWriteRequest,
) {
    let request = request_slot.read_volatile();
    let index = core::ptr::addr_of!((*request).slot_index).read_volatile();
    #[cfg(target_os = "none")]
    let release: OwnerRelease = core::mem::transmute(0x081e_f3a0usize);
    #[cfg(not(target_os = "none"))]
    let release = core::ptr::addr_of!(OWNER_CLOSE_RELEASE).read_volatile();
    release(owner, index);
    core::ptr::addr_of_mut!((*request).status).write_volatile(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut SLOT: *mut *mut OwnerWriteRequest = core::ptr::null_mut();
    static mut REPLACEMENT: *mut OwnerWriteRequest = core::ptr::null_mut();
    static mut EXPECTED_INDEX: i32 = 0;

    unsafe extern "C" fn release(_owner: *const SlotArrayOwner, index: i32) {
        assert_eq!(index, EXPECTED_INDEX);
        let request = SLOT.read();
        assert_eq!((*request).status, 0xdead_beef, "status cleared before release");
        // Simulate reentrant replacement of the queue slot and a status write.
        (*request).status = 17;
        SLOT.write(REPLACEMENT);
    }

    fn request(index: i32) -> OwnerWriteRequest {
        OwnerWriteRequest { opaque_00_to_10: [0; 5], observer: 0,
            opaque_18_to_1c: [0; 2], source: 123, length: 456,
            status: 0xdead_beef, written: 789, file_length: 987, slot_index: index }
    }

    #[test]
    fn clears_original_status_after_release_even_for_invalid_indices() {
        let _guard = LOCK.lock();
        unsafe {
            let saved = OWNER_CLOSE_RELEASE;
            OWNER_CLOSE_RELEASE = release;
            for index in [i32::MIN, -1, 0, i32::MAX] {
                let mut original = request(index);
                let mut replacement = request(12);
                let mut slot = &mut original as *mut OwnerWriteRequest;
                SLOT = &mut slot;
                REPLACEMENT = &mut replacement;
                EXPECTED_INDEX = index;
                let owner = [0u32; 6]; // Includes retail lock storage at +0x14.
                slot_array_owner_close_request(owner.as_ptr().cast(), &slot);
                assert_eq!(slot, &mut replacement as *mut OwnerWriteRequest);
                assert_eq!(original.status, 0);
                assert_eq!(replacement.status, 0xdead_beef);
                assert_eq!((original.source, original.length, original.written,
                    original.file_length, original.slot_index), (123, 456, 789, 987, index));
            }
            OWNER_CLOSE_RELEASE = saved;
            SLOT = core::ptr::null_mut();
            REPLACEMENT = core::ptr::null_mut();
        }
    }
}
