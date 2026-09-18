//! `vtable_08980110_construct` — retailOS `FUN_080fe850` at `0x080fe850`.
//!
//! True size: 28 bytes — six instruction words at `0x080fe850..0x080fe864`
//! followed by the literal-pool vtable word `0x08980110` at `0x080fe868`; the
//! next real function begins at `0x080fe86c`. A whole-image A32 decode finds
//! four inbound plain `bl` instructions (`0x0817e638`, `0x081fa708`,
//! `0x081fae98`, and `0x0820b934`) and no predicated `bl` instructions. The
//! body makes one plain `bl`, to the unrecovered `0x083cfdc4`.
//!
//! Installs its vtable at the outer object, calls the unrecovered base
//! constructor on the embedded object at `this + 8`, and translates that
//! base return pointer back to the outer object by subtracting eight. Target
//! builds call the verified raw-address seam; host tests install a model.
//! Deliberate deviation: the unrecovered callee has no established semantic
//! identity, so it remains an address-specific seam.

#[cfg(not(target_os = "none"))]
use core::ptr;

const VTABLE_ADDRESS: u32 = 0x0898_0110;
const RETAIL_BASE_CONSTRUCT: usize = 0x083c_fdc4;

type BaseConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(_base: *mut u8) -> *mut u8 {
    panic!("install vtable_08980110_construct host seam before calling this port")
}

/// Host boundary for the unrecovered base constructor at `0x083cfdc4`.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08980110_CONSTRUCT_OPS: BaseConstruct = missing_base_construct;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn base_construct(base: *mut u8) -> *mut u8 {
    let construct: BaseConstruct = unsafe { core::mem::transmute(RETAIL_BASE_CONSTRUCT) };
    unsafe { construct(base) }
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn base_construct(base: *mut u8) -> *mut u8 {
    let construct = unsafe { ptr::read_volatile(ptr::addr_of!(VTABLE_08980110_CONSTRUCT_OPS)) };
    unsafe { construct(base) }
}

/// Constructs the vtable-backed outer object and returns the outer pointer.
///
/// # Safety
///
/// `this` must be writable through its vtable word and its embedded base at
/// offset eight must satisfy the unrecovered base constructor's requirements.
/// The ARM body has no null or alignment checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_08980110_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_08980110_construct(this: *mut u8) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_ADDRESS);
        base_construct(this.add(8)).sub(8)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SEEN_BASE: *mut u8 = core::ptr::null_mut();
    static mut SEEN_VTABLE: u32 = 0;

    unsafe extern "C" fn recording_base_construct(base: *mut u8) -> *mut u8 {
        unsafe {
            SEEN_BASE = base;
            SEEN_VTABLE = base.sub(8).cast::<u32>().read();
            base.cast::<u32>().write(0xfeed_face);
        }
        base
    }

    #[repr(align(4))]
    struct Storage([u8; 24]);

    #[test]
    fn installs_vtable_before_constructing_embedded_base() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { VTABLE_08980110_CONSTRUCT_OPS };
        unsafe {
            VTABLE_08980110_CONSTRUCT_OPS = recording_base_construct;
            SEEN_BASE = core::ptr::null_mut();
            SEEN_VTABLE = 0;
        }

        let mut storage = Storage([0xa5; 24]);
        let this = storage.0.as_mut_ptr();
        let returned = unsafe { vtable_08980110_construct(this) };

        unsafe { VTABLE_08980110_CONSTRUCT_OPS = previous };
        assert_eq!(returned, this);
        assert_eq!(unsafe { SEEN_BASE }, unsafe { this.add(8) });
        assert_eq!(unsafe { SEEN_VTABLE }, VTABLE_ADDRESS);
        assert_eq!(unsafe { this.cast::<u32>().read() }, VTABLE_ADDRESS);
        assert_eq!(unsafe { this.add(8).cast::<u32>().read() }, 0xfeed_face);
        assert_eq!(&storage.0[4..8], &[0xa5; 4]);
        assert_eq!(&storage.0[12..], &[0xa5; 12]);
    }
}
