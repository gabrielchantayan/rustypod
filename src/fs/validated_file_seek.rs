//! Validated backing-stream seek — `FUN_0805b804` @ `0x0805b804`.
//!
//! True extent: 48 bytes, [0x0805b804, 0x0805b834); the next function
//! begins with PUSH. Raw A32 decoding finds one plain outbound BL to
//! stream_handle_validate, zero predicated BLs, and a conditional tail B
//! to 0x0805a73c. Two plain inbound BLs occur at 0x08042d9c and
//! 0x08043234; there are no predicated inbound BLs. Ghidra's 100-byte
//! extent and single-argument signature incorrectly absorb the tail target.
//!
//! Validate the mrts tag before reading the descriptor at word 1, then
//! seek to the full 64-bit absolute position and return the backend status.
//! Deliberate deviation: call the existing Rust validator and retain the
//! unported seek/error-translation wrapper as a volatile retail seam.

use core::ptr::{addr_of, read_volatile};

/// Verified AAPCS ABI of 0x0805a73c: descriptor in r0, position in r2:r3.
/// That body rejects descriptor -1, calls 0x082787b8 with origin zero,
/// and tail-translates nonzero errors through 0x0809da3c.
pub type FileSeekBackend = unsafe extern "C" fn(u32, u64) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_file_seek(descriptor: u32, position: u64) -> i32 {
    let seek: FileSeekBackend = core::mem::transmute(0x0805a73cusize);
    seek(descriptor, position)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_file_seek(_: u32, _: u64) -> i32 {
    panic!("validated_file_seek requires retail backend 0x0805a73c")
}

pub static mut FILE_SEEK_BACKEND: FileSeekBackend = firmware_file_seek;

/// # Safety
/// A non-null handle must be word-aligned and readable for its tag. A valid
/// handle must also have a descriptor at word 1 satisfying the retail backend.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn validated_file_seek(handle: *const u32, position: u64) -> i32 {
    let status = crate::stream_handle_validate::stream_handle_validate(handle);
    if status != 0 {
        return status;
    }
    let descriptor = handle.add(1).read();
    let seek = read_volatile(addr_of!(FILE_SEEK_BACKEND));
    seek(descriptor, position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_handles_need_neither_descriptor_nor_backend() {
        unsafe {
            for position in [0, 1, 0xffff_ffff, 0x1_0000_0000, u64::MAX] {
                assert_eq!(validated_file_seek(core::ptr::null(), position), -50);
                // Only the tag exists: rejected handles cannot read word 1.
                for tag in [0, u32::MAX, crate::stream_handle_validate::MRTS_TAG ^ 1] {
                    assert_eq!(validated_file_seek(&tag, position), -50);
                }
            }
        }
    }
}
