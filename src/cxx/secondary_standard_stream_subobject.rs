//! `secondary_standard_stream_subobject` — original: `FUN_083d6ec4` @
//! **0x083d6ec4** (68 bytes).
//!
//! Raw `osos.dec` establishes the A32 body at 0x083d6ec4..0x083d6f07;
//! the literal pointer at 0x083d6f08 is not code, and the next function
//! starts at 0x083d6f0c. The body has one plain `bl` (0x083d6ecc) and no
//! predicated `bl` instructions. A whole-image decode finds two inbound
//! call sites: `blne` at 0x083d8458 and plain `bl` at 0x083d84b0.
//!
//! # Algorithm
//!
//! Recover the complete-object address by adding the signed offset-to-top
//! word immediately before the vtable pointer. The preceding helper checks
//! the first standard-stream subobject slot; this routine accepts either of
//! the remaining two pointers in the three-word table at 0x08b316e8.
//!
//! # Deliberate deviation
//!
//! The unported primary-subobject helper retains its verified load address
//! 0x083d6e9c on target builds and uses a replaceable host seam. The target
//! table is likewise a replaceable native-width host seam so tests do not
//! dereference firmware RAM; target builds use its verified fixed address.

use core::ffi::c_void;

const STANDARD_STREAM_SUBOBJECTS_ADDRESS: usize = 0x08b3_16e8;

type PrimaryStandardStreamSubobject = unsafe extern "C" fn(*const *const i32) -> u32;
type StandardStreamSubobjects = *const *const c_void;


#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn primary_standard_stream_subobject() -> PrimaryStandardStreamSubobject {
    unsafe { core::mem::transmute(0x083d_6e9cusize) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_primary_standard_stream_subobject(_subobject: *const *const i32) -> u32 {
    panic!("install primary-standard-stream-subobject host seam before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut PRIMARY_STANDARD_STREAM_SUBOBJECT: PrimaryStandardStreamSubobject =
    missing_primary_standard_stream_subobject;
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn standard_stream_subobjects() -> StandardStreamSubobjects {
    STANDARD_STREAM_SUBOBJECTS_ADDRESS as StandardStreamSubobjects
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_standard_stream_subobjects() -> StandardStreamSubobjects {
    panic!("install standard-stream-subobject host seam before calling this port")
}

#[cfg(not(target_os = "none"))]
pub static mut STANDARD_STREAM_SUBOBJECTS: unsafe extern "C" fn() -> StandardStreamSubobjects =
    missing_standard_stream_subobjects;

/// Checks whether `subobject` is either secondary standard-stream subobject.
///
/// # Safety
///
/// `subobject` must point to a target-width vtable pointer whose preceding
/// three words include its signed offset-to-top. The standard-stream table
/// and its second and third pointer words must be readable. RetailOS performs
/// no null, alignment, or lifetime validation.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.secondary_standard_stream_subobject")]
#[inline(never)]
pub unsafe extern "C" fn secondary_standard_stream_subobject(
    subobject: *const *const i32,
) -> u32 {
    #[cfg(target_os = "none")]
    let is_primary = unsafe { primary_standard_stream_subobject()(subobject) };
    #[cfg(not(target_os = "none"))]
    let is_primary = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(PRIMARY_STANDARD_STREAM_SUBOBJECT))(subobject)
    };
    if is_primary != 0 {
        return 1;
    }

    let vtable = unsafe { core::ptr::read_volatile(subobject) };
    let offset_to_top = unsafe { core::ptr::read_volatile(vtable.sub(3)) };
    let complete_object = unsafe { subobject.cast::<u8>().offset(offset_to_top as isize) }.cast::<c_void>();

    #[cfg(target_os = "none")]
    let standard_streams = unsafe { standard_stream_subobjects() };
    #[cfg(not(target_os = "none"))]
    let standard_streams = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STANDARD_STREAM_SUBOBJECTS))() };

    let second = unsafe { core::ptr::read_volatile(standard_streams.add(1)) };
    if complete_object == second {
        return 1;
    }

    u32::from(complete_object == unsafe { core::ptr::read_volatile(standard_streams.add(2)) })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut STANDARD_STREAMS: [*const c_void; 3] = [core::ptr::null(); 3];
    static mut PRIMARY_RESULT: u32 = 0;

    unsafe extern "C" fn primary_standard_stream_subobject(_subobject: *const *const i32) -> u32 {
        unsafe { PRIMARY_RESULT }
    }

    unsafe extern "C" fn standard_streams() -> StandardStreamSubobjects {
        core::ptr::addr_of!(STANDARD_STREAMS).cast()
    }

    #[repr(C)]
    struct VtablePrefix {
        offset_to_top: [i32; 3],
        vtable: i32,
    }

    #[test]
    fn accepts_only_the_second_and_third_standard_stream_subobjects() {
        let _guard = TEST_LOCK.lock();
        let vtable = VtablePrefix { offset_to_top: [0, 0, 0], vtable: 0 };
        let second_vtable = &vtable.vtable as *const i32;
        let third_vtable = &vtable.vtable as *const i32;
        let other_vtable = &vtable.vtable as *const i32;
        let second_subobject = core::ptr::addr_of!(second_vtable).cast::<c_void>();
        let third_subobject = core::ptr::addr_of!(third_vtable).cast::<c_void>();

        unsafe {
            PRIMARY_STANDARD_STREAM_SUBOBJECT = primary_standard_stream_subobject;
            STANDARD_STREAM_SUBOBJECTS = standard_streams;
            STANDARD_STREAMS = [core::ptr::null(), second_subobject, third_subobject];
            assert_eq!(secondary_standard_stream_subobject(core::ptr::addr_of!(second_vtable)), 1);
            assert_eq!(secondary_standard_stream_subobject(core::ptr::addr_of!(third_vtable)), 1);
            assert_eq!(secondary_standard_stream_subobject(core::ptr::addr_of!(other_vtable)), 0);
        }
    }

    #[test]
    fn primary_helper_result_short_circuits_the_secondary_table() {
        let _guard = TEST_LOCK.lock();
        let vtable = VtablePrefix { offset_to_top: [0, 0, 0], vtable: 0 };
        let object_vtable = &vtable.vtable as *const i32;

        unsafe {
            PRIMARY_STANDARD_STREAM_SUBOBJECT = primary_standard_stream_subobject;
            PRIMARY_RESULT = 1;
            assert_eq!(secondary_standard_stream_subobject(core::ptr::addr_of!(object_vtable)), 1);
            PRIMARY_RESULT = 0;
        }
    }
}
