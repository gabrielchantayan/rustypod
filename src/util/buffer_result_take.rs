//! `buffer_result_take_and_release` — original: `FUN_082c691c` @ **0x082c691c**.
//!
//! Raw ARM is exactly **136 bytes**: 32 instruction words from
//! `0x082c691c..0x082c699c`, followed by its owned error-code literal at
//! `0x082c69a4`; the next function begins at `0x082c69a8`. Decoding the words
//! finds **6 `bl` instructions**, all unconditional and none predicated.
//!
//! # Algorithm
//!
//! Validates an owner, output pointer, a <= 4096-byte buffered result, and
//! the invariant that the active-data pointer names the 20-byte result field.
//! It marks the buffer busy, invokes the stock buffer transform, copies that
//! 20-byte result out, clears the 64-byte header and 4096-byte payload, then
//! releases the owner and deletes its buffer.
//!
//! # Deliberate deviations
//!
//! The transform at `0x08064fb8` and owner release at `0x0839e164` are not
//! ported, so target builds call their verified raw addresses. Host builds use
//! replaceable inert seams; tests record their exact arguments and ordering.

#[cfg(target_os = "none")]
use crate::heap::veneers::operator_delete;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::iram_veneers::iram_memzero_veneer;

const ERROR_INVALID_BUFFER_RESULT: u32 = 0xffff_5bd9;
const MAX_BUFFERED_RESULT: u32 = 0x1000;
const RESULT_SIZE: usize = 0x14;
const BUFFER_HEADER_SIZE: usize = 0x40;

type BufferTransform = unsafe extern "C" fn(*mut u8, *mut u8, u32);
type OwnerRelease = unsafe extern "C" fn(*mut u8);
type BufferDelete = unsafe extern "C" fn(*mut u8);

#[cfg(target_os = "none")]
unsafe fn transform_buffer(buffer: *mut u8, payload: *mut u8, len: u32) {
    let transform: BufferTransform = core::mem::transmute(0x0806_4fb8usize);
    transform(buffer, payload, len);
}

#[cfg(target_os = "none")]
unsafe fn release_owner(owner: *mut u8) {
    let release: OwnerRelease = core::mem::transmute(0x0839_e164usize);
    release(owner);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn inert_transform_buffer(_buffer: *mut u8, _payload: *mut u8, _len: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn inert_release_owner(_owner: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn inert_buffer_delete(_buffer: *mut u8) {}

#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn transform_buffer(buffer: *mut u8, payload: *mut u8, len: u32) {
    inert_transform_buffer(buffer, payload, len);
}
#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn release_owner(owner: *mut u8) { inert_release_owner(owner); }
#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn delete_buffer(buffer: *mut u8) { inert_buffer_delete(buffer); }

#[cfg(test)]
static mut BUFFER_TRANSFORM: BufferTransform = inert_transform_buffer;
#[cfg(test)]
static mut OWNER_RELEASE: OwnerRelease = inert_release_owner;
#[cfg(test)]
static mut BUFFER_DELETE: BufferDelete = inert_buffer_delete;
#[cfg(test)]
unsafe fn transform_buffer(buffer: *mut u8, payload: *mut u8, len: u32) { BUFFER_TRANSFORM(buffer, payload, len); }
#[cfg(test)]
unsafe fn release_owner(owner: *mut u8) { OWNER_RELEASE(owner); }
#[cfg(test)]
unsafe fn delete_buffer(buffer: *mut u8) { BUFFER_DELETE(buffer); }

/// Takes a 20-byte buffered result and releases its owner.
///
/// # Safety
/// `owner` must be either NULL or point to the target-layout object whose
/// word at +0x04 is a valid 0x106c-byte buffer. `out` must be NULL or writable
/// for 20 bytes. A valid call consumes both objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.buffer_result_take_and_release")]
#[inline(never)]
pub unsafe extern "C" fn buffer_result_take_and_release(owner: *mut u8, out: *mut u8) -> u32 {
    if owner.is_null() || out.is_null() {
        return ERROR_INVALID_BUFFER_RESULT;
    }

    let buffer = (owner.add(4) as *const u32).read_volatile() as usize as *mut u8;
    let payload_len = (buffer.add(0x68) as *const u32).read_volatile();
    if payload_len > MAX_BUFFERED_RESULT || (buffer.add(0x4c) as *const u32).read_volatile() != buffer.add(0x54) as usize as u32 {
        return ERROR_INVALID_BUFFER_RESULT;
    }

    (buffer.add(0x50) as *mut u32).write_volatile(2);
    transform_buffer(buffer, buffer.add(0x6c), payload_len);
    __rt_memcpy(out, buffer.add(0x54), RESULT_SIZE);
    iram_memzero_veneer(buffer, BUFFER_HEADER_SIZE);
    iram_memzero_veneer(buffer.add(0x6c), MAX_BUFFERED_RESULT as usize);
    release_owner(owner);
    #[cfg(target_os = "none")]
    operator_delete(buffer);
    #[cfg(not(target_os = "none"))]
    delete_buffer(buffer);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u32; 3] = [0; 3];
    static mut TRANSFORM_BUFFER: *mut u8 = core::ptr::null_mut();
    static mut TRANSFORM_PAYLOAD: *mut u8 = core::ptr::null_mut();
    static mut TRANSFORM_LEN: u32 = 0;

    unsafe extern "C" fn record_transform(buffer: *mut u8, payload: *mut u8, len: u32) {
        EVENTS[0] = 1; TRANSFORM_BUFFER = buffer; TRANSFORM_PAYLOAD = payload; TRANSFORM_LEN = len;
        for i in 0..RESULT_SIZE { buffer.add(0x54 + i).write((0xa0 + i) as u8); }
    }
    unsafe extern "C" fn record_release(_owner: *mut u8) { EVENTS[1] = 2; }
    unsafe extern "C" fn record_delete(_buffer: *mut u8) { EVENTS[2] = 3; }

    struct Restore(BufferTransform, OwnerRelease, BufferDelete);
    impl Drop for Restore { fn drop(&mut self) { unsafe { BUFFER_TRANSFORM = self.0; OWNER_RELEASE = self.1; BUFFER_DELETE = self.2; } } }

    #[test]
    fn takes_result_then_clears_and_releases() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BUFFER_RESULT_TAKE, 0x3000) else { assert!(note_missing_u32_fixture("util/buffer_result_take")); return; };
        unsafe {
            let owner = slab.add(0x100); let buffer = slab.add(0x400); let out = slab.add(0x1800);
            (owner.add(4) as *mut u32).write(buffer as usize as u32);
            (buffer.add(0x4c) as *mut u32).write(buffer.add(0x54) as usize as u32);
            (buffer.add(0x68) as *mut u32).write(7);
            core::ptr::write_bytes(buffer, 0xcc, 0x106c);
            (buffer.add(0x4c) as *mut u32).write(buffer.add(0x54) as usize as u32);
            (buffer.add(0x68) as *mut u32).write(7);
            EVENTS = [0; 3];
            let _restore = Restore(BUFFER_TRANSFORM, OWNER_RELEASE, BUFFER_DELETE);
            BUFFER_TRANSFORM = record_transform; OWNER_RELEASE = record_release; BUFFER_DELETE = record_delete;
            assert_eq!(buffer_result_take_and_release(owner, out), 0);
            assert_eq!(EVENTS, [1, 2, 3]); assert_eq!(TRANSFORM_BUFFER, buffer); assert_eq!(TRANSFORM_PAYLOAD, buffer.add(0x6c)); assert_eq!(TRANSFORM_LEN, 7);
            assert_eq!(core::slice::from_raw_parts(out, RESULT_SIZE), &[0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3]);
            assert!(core::slice::from_raw_parts(buffer, BUFFER_HEADER_SIZE).iter().all(|&b| b == 0));
            assert!(core::slice::from_raw_parts(buffer.add(0x6c), 0x1000).iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn rejects_null_oversize_and_noncanonical_result_pointer() {
        let _lock = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::BUFFER_RESULT_TAKE_REJECT, 0x3000) else { assert!(note_missing_u32_fixture("util/buffer_result_take")); return; };
        unsafe {
            let owner = slab.add(0x100); let buffer = slab.add(0x400); let out = slab.add(0x1800);
            assert_eq!(buffer_result_take_and_release(core::ptr::null_mut(), out), ERROR_INVALID_BUFFER_RESULT);
            assert_eq!(buffer_result_take_and_release(owner, core::ptr::null_mut()), ERROR_INVALID_BUFFER_RESULT);
            (owner.add(4) as *mut u32).write(buffer as usize as u32);
            (buffer.add(0x4c) as *mut u32).write(buffer.add(0x54) as usize as u32);
            (buffer.add(0x68) as *mut u32).write(0x1001);
            assert_eq!(buffer_result_take_and_release(owner, out), ERROR_INVALID_BUFFER_RESULT);
            (buffer.add(0x68) as *mut u32).write(0); (buffer.add(0x4c) as *mut u32).write(0);
            assert_eq!(buffer_result_take_and_release(owner, out), ERROR_INVALID_BUFFER_RESULT);
        }
    }
}
