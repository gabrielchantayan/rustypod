//! `transfer_payload_read` — FUN_08189034 @ 0x08189034.
//! True extent: 180 bytes to 0x081890e8 (172 code bytes, 8 literal bytes).
//! Two plain outbound BLs, zero predicated BLs, one virtual BLX; two plain
//! inbound BLs and zero predicated inbound BLs, independently decoded from raw A32.
//!
//! Selects a kind-specific tag, invokes the resident transfer-header reader,
//! caps its signed payload length at 0x2800, allocates with caller tag 3, and
//! reads through stream vtable slot four in mode 2. Header failure leaves both
//! outputs untouched; allocation failure clears length; short reads retain
//! the allocation and requested length. Zero and negative lengths are not guarded.
//! Deviations: fixed-address header call becomes an indirect Rust call; repr(C)
//! stream/vtable pointers widen on hosts. Host seams replace resident services.

use crate::heap::veneers::operator_new_tag3;

type ReadHeader = unsafe extern "C" fn(*mut u8, *mut TransferStream, u32, u32, u32) -> u32;
type ReadPayload = unsafe extern "C" fn(*mut TransferStream, *mut u8, i32, u32) -> i32;

#[repr(C)]
pub struct TransferStream {
    pub vtable: *const TransferStreamVtable,
}

#[repr(C)]
pub struct TransferStreamVtable {
    pub preceding_slots: [usize; 4],
    pub read: ReadPayload,
}

#[cfg(not(target_os = "none"))]
static mut HOST_READ_HEADER: Option<ReadHeader> = None;
#[cfg(test)]
static mut HOST_ALLOCATE: unsafe extern "C" fn(usize) -> *mut u8 = operator_new_tag3;

unsafe fn read_header(record: *mut u8, stream: *mut TransferStream, position: u32, flags: u32, tag: u32) -> u32 {
    #[cfg(target_os = "none")]
    let read: ReadHeader = core::mem::transmute(0x0810_59a0usize);
    #[cfg(not(target_os = "none"))]
    let read = core::ptr::read(core::ptr::addr_of!(HOST_READ_HEADER))
        .expect("transfer header reader requires a host seam");
    read(record, stream, position, flags, tag)
}

unsafe fn allocate(size: usize) -> *mut u8 {
    #[cfg(test)]
    { HOST_ALLOCATE(size) }
    #[cfg(not(test))]
    { operator_new_tag3(size) }
}

/// Reads an owned bounded payload; returns 0 only for an exact read, else 1.
///
/// # Safety
/// `record` has a writable aligned i32 at +0 and a readable kind byte at +4.
/// The resident header reader requires its original record/stream contract.
/// `stream` has a valid slot-four read method. Outputs are writable and the
/// caller owns any published allocation, including on a short-read failure.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transfer_payload_read(
    record: *mut u8, stream: *mut TransferStream, position: u32, flags: u32,
    buffer_out: *mut *mut u8, length_out: *mut i32,
) -> u32 {
    let tag = match record.add(4).read() {
        2 => 0x554c_5400,
        3 | 4 => 0x5553_4c54,
        _ => flags,
    };
    if read_header(record, stream, position, flags, tag) != 0 {
        return 1;
    }
    let length = record.cast::<i32>().read().min(0x2800);
    length_out.write(length);
    let buffer = allocate(length as u32 as usize);
    buffer_out.write(buffer);
    if buffer.is_null() {
        length_out.write(0);
        return 1;
    }
    let read = (*(*stream).vtable).read;
    let count = read(stream, buffer, length_out.read(), 2);
    if count == length_out.read() { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut HEADER_STATUS: u32 = 0;
    static mut ALLOC_FAIL: bool = false;
    static mut SHORT_READ: bool = false;
    static mut SIZE: usize = 0;
    static mut STORAGE: [u8; 0x2800] = [0; 0x2800];

    unsafe extern "C" fn header(record: *mut u8, _: *mut TransferStream, position: u32, flags: u32, tag: u32) -> u32 {
        assert_eq!(position, 0x12345678);
        assert_eq!(flags, 0x87654321);
        assert_eq!(tag, match record.add(4).read() { 2 => 0x554c5400, 3 | 4 => 0x55534c54, _ => flags });
        HEADER_STATUS
    }
    unsafe extern "C" fn alloc(size: usize) -> *mut u8 {
        SIZE = size;
        if ALLOC_FAIL { ptr::null_mut() } else { ptr::addr_of_mut!(STORAGE).cast() }
    }
    unsafe extern "C" fn read(_: *mut TransferStream, buffer: *mut u8, length: i32, mode: u32) -> i32 {
        assert_eq!(mode, 2);
        for i in 0..length.max(0) as usize { buffer.add(i).write((i as u8) ^ 0x5a); }
        if SHORT_READ { length.wrapping_sub(1) } else { length }
    }

    #[test]
    fn payload_boundaries_and_failure_transitions() {
        let _lock = LOCK.lock();
        unsafe {
            let old_header = HOST_READ_HEADER;
            let old_alloc = HOST_ALLOCATE;
            HOST_READ_HEADER = Some(header);
            HOST_ALLOCATE = alloc;
            let vtable = TransferStreamVtable { preceding_slots: [0; 4], read };
            let mut stream = TransferStream { vtable: &vtable };
            for kind in [0u8, 2, 3, 4, 255] {
                for input in [i32::MIN, -1, 0, 1, 0x27ff, 0x2800, 0x2801, i32::MAX] {
                    let mut record = [input as u32, kind as u32, 0];
                    for failure in 0..4 {
                        HEADER_STATUS = if failure == 1 { 7 } else { 0 };
                        ALLOC_FAIL = failure == 2;
                        SHORT_READ = failure == 3;
                        SIZE = usize::MAX;
                        let mut buffer = ptr::dangling_mut::<u8>();
                        let mut length = -123;
                        let result = transfer_payload_read(record.as_mut_ptr().cast(), &mut stream,
                            0x12345678, 0x87654321, &mut buffer, &mut length);
                        assert_eq!(result, if failure == 0 { 0 } else { 1 });
                        if failure == 1 {
                            assert_eq!(buffer, ptr::dangling_mut::<u8>());
                            assert_eq!(length, -123);
                            assert_eq!(SIZE, usize::MAX);
                        } else {
                            let expected = input.min(0x2800);
                            assert_eq!(SIZE, expected as u32 as usize);
                            assert_eq!(length, if failure == 2 { 0 } else { expected });
                            if failure == 2 { assert!(buffer.is_null()); }
                            else {
                                assert_eq!(buffer, ptr::addr_of_mut!(STORAGE).cast::<u8>());
                                for i in 0..expected.max(0) as usize {
                                    assert_eq!(buffer.add(i).read(), (i as u8) ^ 0x5a);
                                }
                            }
                        }
                    }
                }
            }
            HOST_READ_HEADER = old_header;
            HOST_ALLOCATE = old_alloc;
        }
    }
}
