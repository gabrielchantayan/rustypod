//! Writes a buffer through an initialized BIO handle.
//!
//! Port: `bio_handle_write` — `FUN_082d4438` @ **0x082d4438** (60 bytes,
//! `0x082d4438..0x082d4474`; the next separately linked function begins at
//! `0x082d4474`). Raw ARM decoding finds four inbound `bl` call sites: one
//! unconditional (`0x0816482c`) and three `blne` (`0x08196618`, `0x08196c00`,
//! `0x08196c64`). The body has one unconditional `bl`, to the verified
//! `BIO_write` seam at `0x0803da74`.
//!
//! # Algorithm
//!
//! Null handles or buffers return 1. A handle whose leading kind byte is not
//! 1 returns 14. Otherwise it writes the supplied signed byte count through
//! the BIO pointer at +0x10; a positive BIO result maps to 0 and zero or a
//! negative result maps to 11.
//!
//! # Deliberate deviations
//!
//! `BIO_write` remains unported. Firmware builds call its verified retailOS
//! address directly; host builds use a volatile seam because target BIO
//! pointers are 32-bit while host function pointers and allocations may not be.

use super::bio_ctrl::Bio;

const BIO_WRITE_ADDRESS: usize = 0x0803_da74;

/// The 20-byte target handle observed by this wrapper.
#[repr(C)]
pub struct BioWriteHandle {
    /// +0x00 — initialized kind, required to be one.
    pub kind: u8,
    /// +0x01..+0x0f — state not observed by this function.
    pub _reserved: [u8; 15],
    /// +0x10 — `BIO *`, retained as a target-width pointer.
    pub bio: u32,
}

/// ABI of retailOS `BIO_write`.
pub type BioWriteFn = unsafe extern "C" fn(*mut Bio, *const u8, i32) -> i32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_write(_bio: *mut Bio, _data: *const u8, _len: i32) -> i32 {
    panic!("bio_handle_write requires BIO_write at 0x0803da74")
}

/// Host-only replacement for the target-width `BIO_write` entry.
#[cfg(not(target_os = "none"))]
pub static mut BIO_WRITE: BioWriteFn = missing_bio_write;

#[inline(always)]
unsafe fn bio_write(bio: *mut Bio, data: *const u8, len: i32) -> i32 {
    #[cfg(target_os = "none")]
    {
        let write: BioWriteFn = unsafe { core::mem::transmute(BIO_WRITE_ADDRESS) };
        unsafe { write(bio, data, len) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let write = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(BIO_WRITE)) };
        unsafe { write(bio, data, len) }
    }
}

/// # Safety
/// `handle` must be null or point to a live target-layout [`BioWriteHandle`].
/// A nonzero `handle.bio` with `kind == 1` must point to a BIO accepted by the
/// retail `BIO_write` ABI; `data` and `len` are passed through unchanged.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.bio_handle_write")]
pub unsafe extern "C" fn bio_handle_write(
    handle: *const BioWriteHandle,
    data: *const u8,
    len: i32,
) -> u32 {
    if handle.is_null() || data.is_null() {
        return 1;
    }
    if unsafe { (*handle).kind } != 1 {
        return 14;
    }

    let bio = unsafe { (*handle).bio as usize as *mut Bio };
    if unsafe { bio_write(bio, data, len) } > 0 {
        0
    } else {
        11
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use parking_lot::Mutex;

    use super::*;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut BIO_RESULT: i32 = 0;
    static mut OBSERVED_BIO: *mut Bio = ptr::null_mut();
    static mut OBSERVED_DATA: *const u8 = ptr::null();
    static mut OBSERVED_LEN: i32 = 0;

    unsafe fn reset_observed() {
        unsafe {
            OBSERVED_BIO = ptr::null_mut();
            OBSERVED_DATA = ptr::null();
            OBSERVED_LEN = 0;
        }
    }

    unsafe extern "C" fn record_bio_write(bio: *mut Bio, data: *const u8, len: i32) -> i32 {
        unsafe {
            OBSERVED_BIO = bio;
            OBSERVED_DATA = data;
            OBSERVED_LEN = len;
            BIO_RESULT
        }
    }

    struct Seam(BioWriteFn);

    impl Seam {
        unsafe fn install() -> Self {
            unsafe {
                let old = BIO_WRITE;
                BIO_WRITE = record_bio_write;
                Self(old)
            }
        }
    }

    impl Drop for Seam {
        fn drop(&mut self) {
            unsafe { BIO_WRITE = self.0 };
        }
    }

    #[test]
    fn rejects_null_handle_or_buffer_without_writing() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { Seam::install() };
        unsafe { reset_observed() };
        let data = [0u8; 1];
        let handle = BioWriteHandle { kind: 1, _reserved: [0; 15], bio: 0 };

        assert_eq!(unsafe { bio_handle_write(ptr::null(), data.as_ptr(), 1) }, 1);
        assert_eq!(unsafe { bio_handle_write(&handle, ptr::null(), 1) }, 1);
        assert!(unsafe { OBSERVED_BIO.is_null() });
    }

    #[test]
    fn rejects_wrong_handle_kind_without_writing() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { Seam::install() };
        unsafe { reset_observed() };
        let data = [0u8; 1];
        let handle = BioWriteHandle { kind: 0, _reserved: [0; 15], bio: 0 };

        assert_eq!(unsafe { bio_handle_write(&handle, data.as_ptr(), -1) }, 14);
        assert!(unsafe { OBSERVED_BIO.is_null() });
    }

    #[test]
    fn maps_positive_write_to_success_and_preserves_arguments() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { Seam::install() };
        unsafe { reset_observed() };
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::BIO_HANDLE_WRITE, 64) else {
            return;
        };
        let data = [9u8, 8, 7];
        let handle = BioWriteHandle { kind: 1, _reserved: [0; 15], bio: slab as usize as u32 };
        unsafe { BIO_RESULT = 3 };

        assert_eq!(unsafe { bio_handle_write(&handle, data.as_ptr(), -3) }, 0);
        assert_eq!(unsafe { OBSERVED_BIO }, slab.cast());
        assert_eq!(unsafe { OBSERVED_DATA }, data.as_ptr());
        assert_eq!(unsafe { OBSERVED_LEN }, -3);
    }

    #[test]
    fn maps_zero_and_negative_write_to_failure() {
        let _lock = SEAM_LOCK.lock();
        let _seam = unsafe { Seam::install() };
        unsafe { reset_observed() };
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::BIO_HANDLE_WRITE_FAILURE, 64) else {
            return;
        };
        let data = [0u8; 1];
        let handle = BioWriteHandle { kind: 1, _reserved: [0; 15], bio: slab as usize as u32 };

        unsafe { BIO_RESULT = 0 };
        assert_eq!(unsafe { bio_handle_write(&handle, data.as_ptr(), 0) }, 11);
        unsafe { BIO_RESULT = -1 };
        assert_eq!(unsafe { bio_handle_write(&handle, data.as_ptr(), 1) }, 11);
    }
}
