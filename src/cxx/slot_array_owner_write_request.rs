//! Executes a pointer-slot owner's write request.
//!
//! `FUN_081ef0a4` @ `0x081ef0a4`: 112 bytes, ending at the independently
//! entered push at `0x081ef114`. Whole-image A32 decoding finds two inbound
//! plain BLs (0x081eeab0, 0x081eeaf8), zero predicated BLs; the body has five
//! plain BLs and zero predicated BLs.
//!
//! Resolve the indexed handle, clean the source cache range, translate its
//! address, write the requested bytes and store status/count. Only on write
//! success, query length and copy it to the request and optional observer.
//! The query status is ignored; its output starts with incoming r3, preserving
//! even the query's no-output paths. r2 is unused. Deliberate deviations:
//! volatile word accesses retain target layout on hosts; host-only callbacks
//! replace cache hardware and length-query object graphs. Target writes call
//! the original writer: the existing Rust wrapper's shared-core operations
//! default to an unwired no-progress implementation, not the retail core.

use super::slot_array_owner_get::{slot_array_owner_get, SlotArrayOwner};
use crate::drivers::cache_address_translate::cache_address_translate;

#[repr(C)]
pub struct OwnerWriteRequest {
    pub opaque_00_to_10: [u32; 5],
    pub observer: u32,
    pub opaque_18_to_1c: [u32; 2],
    pub source: u32,
    pub length: u32,
    pub status: u32,
    pub written: u32,
    pub file_length: u32,
    pub slot_index: i32,
}

type CleanRange = unsafe extern "C" fn(u32, u32);
type QueryLength = unsafe extern "C" fn(*mut core::ffi::c_void, *mut u32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clean(_source: u32, _length: u32) {
    panic!("install owner-write cache-clean host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_WRITE_CLEAN_RANGE: CleanRange = missing_clean;
#[cfg(not(target_os = "none"))]
pub static mut OWNER_WRITE_QUERY_LENGTH: QueryLength = crate::ft::system::ft_platform_file_length;

#[inline(always)]
unsafe fn clean_range(source: u32, length: u32) {
    #[cfg(target_os = "none")]
    let clean: CleanRange = core::mem::transmute(0x080c_0154usize);
    #[cfg(not(target_os = "none"))]
    let clean = core::ptr::read_volatile(core::ptr::addr_of!(OWNER_WRITE_CLEAN_RANGE));
    clean(source, length);
}

#[inline(always)]
unsafe fn query_length(handle: u32, length: *mut u32) {
    #[cfg(target_os = "none")]
    let query: QueryLength = crate::ft::system::ft_platform_file_length;
    #[cfg(not(target_os = "none"))]
    let query = core::ptr::read_volatile(core::ptr::addr_of!(OWNER_WRITE_QUERY_LENGTH));
    let _ = query(handle as usize as *mut core::ffi::c_void, length);
}

/// # Safety
/// Owner and request slot must be readable; the request must be writable.
/// All target-width pointers and the selected handle must satisfy their
/// callees' contracts. A nonzero observer names at least three writable words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn slot_array_owner_write_request(
    owner: *const SlotArrayOwner,
    request_slot: *const *mut OwnerWriteRequest,
    _unused_r2: u32,
    initial_length: u32,
) {
    let request = request_slot.read_volatile();
    let handle = slot_array_owner_get(owner, core::ptr::addr_of!((*request).slot_index).read_volatile());
    clean_range(core::ptr::addr_of!((*request).source).read_volatile(),
        core::ptr::addr_of!((*request).length).read_volatile());
    let data = cache_address_translate(core::ptr::addr_of!((*request).source).read_volatile());
    #[cfg(target_os = "none")]
    let write: unsafe extern "C" fn(*mut u8, u32, *const u8, *mut u32) -> u32 =
        core::mem::transmute(0x0827_899cusize);
    #[cfg(not(target_os = "none"))]
    let write = super::stream_write::stream_write;
    let status = write(handle as usize as *mut u8,
        core::ptr::addr_of!((*request).length).read_volatile(),
        data as usize as *const u8, core::ptr::addr_of_mut!((*request).written));
    core::ptr::addr_of_mut!((*request).status).write_volatile(status);
    if status == 0 {
        let mut length = initial_length;
        query_length(handle, &mut length);
        core::ptr::addr_of_mut!((*request).file_length).write_volatile(length);
        let observer = core::ptr::addr_of!((*request).observer).read_volatile();
        if observer != 0 {
            (observer as usize as *mut u32).add(2).write_volatile(length);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::stream_write::{STREAM_WRITE_CORE_OPS, STREAM_WRITE_TEST_LOCK, StreamWriteCoreOps};
    use crate::testing::{hints, try_map_u32_slab};
    static mut STATUS: u32 = 0;
    static mut QUERY_MODE: u32 = 0;
    static mut QUERIES: u32 = 0;
    unsafe extern "C" fn clean(_source: u32, _length: u32) {}
    unsafe extern "C" fn write(_handle: *mut u8, length: u32, _data: *const u8, written: *mut u32, _mode: u32) -> u32 {
        written.write(length / 2);
        STATUS
    }
    unsafe extern "C" fn query(_handle: *mut core::ffi::c_void, length: *mut u32) -> i32 {
        QUERIES += 1;
        if QUERY_MODE == 0 { length.write(12345); }
        2 // Caller must ignore even an error status with a modified output.
    }
    #[test]
    fn failure_preserves_lengths_and_success_propagates_query_output_or_seed() {
        let _guard = STREAM_WRITE_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::SLOT_ARRAY_OWNER_WRITE_REQUEST, 4096) else { return; };
        unsafe {
            // SlotArray: storage, count, capacity; index -1 deliberately
            // exercises the real checked getter's null-handle outcome.
            let owner = SlotArrayOwner { opaque_00: 0, opaque_04: 0, opaque_08: 0, slots: slab as u32 };
            core::ptr::write_bytes(slab, 0, 4096);
            let observer = slab.add(0x100).cast::<u32>();
            let old_write = STREAM_WRITE_CORE_OPS;
            let old_clean = OWNER_WRITE_CLEAN_RANGE;
            let old_query = OWNER_WRITE_QUERY_LENGTH;
            STREAM_WRITE_CORE_OPS = StreamWriteCoreOps { core: write };
            OWNER_WRITE_CLEAN_RANGE = clean;
            OWNER_WRITE_QUERY_LENGTH = query;
            for (status, mode, mirror) in [(7, 0, true), (0, 0, true), (0, 1, true), (0, 0, false)] {
                STATUS = status; QUERY_MODE = mode; QUERIES = 0;
                observer.add(2).write(99);
                let mut request = OwnerWriteRequest { opaque_00_to_10: [0; 5], observer: if mirror { observer as u32 } else { 0 }, opaque_18_to_1c: [0; 2], source: 0x1800_0040, length: 13, status: 88, written: 77, file_length: 66, slot_index: -1 };
                let slot = &mut request as *mut OwnerWriteRequest;
                slot_array_owner_write_request(&owner, &slot, 0, 0xfeed);
                assert_eq!(request.status, status);
                assert_eq!(request.written, 6);
                let expected = if status != 0 { 66 } else if mode == 0 { 12345 } else { 0xfeed };
                assert_eq!(request.file_length, expected);
                assert_eq!(observer.add(2).read(), if status == 0 && mirror { expected } else { 99 });
                assert_eq!(QUERIES, u32::from(status == 0));
            }
            STREAM_WRITE_CORE_OPS = old_write;
            OWNER_WRITE_CLEAN_RANGE = old_clean;
            OWNER_WRITE_QUERY_LENGTH = old_query;
        }
    }
}
