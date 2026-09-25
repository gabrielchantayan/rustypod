//! `object_byte_0x450_initialize` — original: `FUN_080faaa0` @ 0x080faaa0
//! (36 bytes; next real function begins at 0x080faac4).
//!
//! Reads the opaque object's byte at `+0x450`. A nonzero value returns without
//! side effects; zero calls the still-unidentified retail helper at 0x0809b644
//! with zero and stores its byte result at `+0x450`. Raw A32 words establish
//! one plain internal `bl` and no predicated `bl` instructions. An independent
//! full-image A32 decode finds three inbound plain `bl` sites (0x080f87d0,
//! 0x080fdc40, and 0x080fdf10) and no predicated forms.
//!
//! Sources: `ipod-decomp/work/firmware/osos.dec`; `ipod-decomp/decomp/c/009/
//! 080faaa0_FUN_080faaa0.c`; callers `FUN_080f87ac`, `FUN_080fdc24`, and
//! `FUN_080fdf08`.
//!
//! Deliberate deviation: the unported 0x0809b644 helper remains address-named;
//! host builds use a seam while target builds call its retail address.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;
#[cfg(test)]
extern crate std;


const RETAIL_0809B644: usize = 0x0809_b644;
pub(crate) type RetailByteInitializer = unsafe extern "C" fn(u32) -> u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retail_byte_initializer(_argument: u32) -> u8 {
    panic!("install object-byte-0x450 host operations before initializing it")
}

/// Host seam for the unidentified retail helper at 0x0809b644.
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_BYTE_0X450_INITIALIZER: RetailByteInitializer = missing_retail_byte_initializer;

#[cfg(test)]
pub(crate) static RETAIL_BYTE_INITIALIZER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[inline(always)]
pub(crate) unsafe fn retail_byte_initializer() -> u8 {
    #[cfg(target_os = "none")]
    {
        let helper: RetailByteInitializer = unsafe { core::mem::transmute(RETAIL_0809B644) };
        return unsafe { helper(0) };
    }
    #[cfg(not(target_os = "none"))]
    {
        let helper = unsafe { core::ptr::read_volatile(addr_of!(OBJECT_BYTE_0X450_INITIALIZER)) };
        unsafe { helper(0) }
    }
}

/// Lazily initializes byte `+0x450` of an opaque object from retail state.
///
/// # Safety
///
/// `object` must point into a readable, writable allocation containing byte
/// `+0x450`. The pointer may be unaligned because the retail routine uses byte
/// accesses.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_byte_0x450_initialize(object: *mut u8) {
    let field = unsafe { object.add(0x450) };
    if unsafe { field.read() } == 0 {
        unsafe { field.write(retail_byte_initializer()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::addr_of_mut;
    static mut CALLS: u32 = 0;
    static mut RESULT: u8 = 0;

    unsafe extern "C" fn recording_initializer(argument: u32) -> u8 {
        assert_eq!(argument, 0);
        unsafe { CALLS += 1 };
        unsafe { RESULT }
    }

    fn install_initializer() {
        unsafe {
            addr_of_mut!(OBJECT_BYTE_0X450_INITIALIZER).write(recording_initializer);
            CALLS = 0;
        }
    }

    #[test]
    fn initializes_zero_field_with_retail_result() {
        let _guard = RETAIL_BYTE_INITIALIZER_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        install_initializer();
        unsafe { RESULT = 0xa5 };
        let mut storage = [0u8; 0x452];
        let object = unsafe { storage.as_mut_ptr().add(1) };

        unsafe { object_byte_0x450_initialize(object) };

        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { object.add(0x450).read() }, 0xa5);
    }

    #[test]
    fn preserves_nonzero_field_without_calling_retail_helper() {
        let _guard = RETAIL_BYTE_INITIALIZER_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        install_initializer();
        unsafe { RESULT = 0 };
        let mut storage = [0xa5u8; 0x452];
        let object = unsafe { storage.as_mut_ptr().add(1) };
        unsafe { object.add(0x450).write(0x80) };

        unsafe { object_byte_0x450_initialize(object) };

        assert_eq!(unsafe { CALLS }, 0);
        assert_eq!(unsafe { object.add(0x450).read() }, 0x80);
    }
}
