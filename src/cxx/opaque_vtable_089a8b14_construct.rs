//! `opaque_vtable_089a8b14_construct` — retailOS `FUN_083e798c` @
//! **0x083e798c** (20 bytes: 16 bytes of code plus the vtable literal at
//! 0x083e79a0).
//!
//! The four code words span 0x083e798c..0x083e7998; literal-pool word
//! 0x089a8b14 at 0x083e79a0 completes the function, and the next separately
//! linked function begins at 0x083e79a4. Raw A32 decoding finds two inbound
//! direct calls, both plain `bl` (0x082a7be4 and 0x082a9174), and no predicated
//! `bl` calls. The function itself has one plain `bl`, to the still-retail base
//! constructor at 0x082a9498, and no predicated calls.
//!
//! # Algorithm
//!
//! Invoke the opaque base constructor, then replace word +0x00 of its returned
//! object with 0x089a8b14. The literal's class identity and the base object's
//! full layout are not recovered, so neither is invented. There are no NULL or
//! alignment checks. Deliberate deviation: the unported base constructor is a
//! replaceable host seam; target builds call its verified retail address.

const RETAIL_BASE_CONSTRUCT_ADDRESS: usize = 0x082a_9498;
/// Vtable-like literal installed after the opaque base construction.
pub const OPAQUE_VTABLE_089A8B14: u32 = 0x089a_8b14;

/// ABI of the still-retail base constructor at `0x082a9498`.
pub type OpaqueBaseConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_base_construct(this: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, OpaqueBaseConstruct>(RETAIL_BASE_CONSTRUCT_ADDRESS)(this) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_construct(_: *mut u8) -> *mut u8 {
    panic!("opaque_vtable_089a8b14_construct requires base constructor 0x082a9498")
}

/// Boundary for the unported base constructor.
#[cfg(target_os = "none")]
pub static mut OPAQUE_BASE_CONSTRUCT: OpaqueBaseConstruct = retail_base_construct;
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_BASE_CONSTRUCT: OpaqueBaseConstruct = missing_base_construct;

#[inline(always)]
fn opaque_base_construct() -> OpaqueBaseConstruct {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(OPAQUE_BASE_CONSTRUCT)) }
}

/// Constructs the opaque derived object and returns the base constructor result.
///
/// # Safety
///
/// `this` must satisfy the base constructor's opaque storage contract, and its
/// returned pointer must identify at least one writable, word-aligned target word.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_vtable_089a8b14_construct")]
#[inline(never)]
pub unsafe extern "C" fn opaque_vtable_089a8b14_construct(this: *mut u8) -> *mut u8 {
    let constructed = unsafe { opaque_base_construct()(this) };
    unsafe { constructed.cast::<u32>().write_volatile(OPAQUE_VTABLE_089A8B14) };
    constructed
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut BASE_INPUT: *mut u8 = core::ptr::null_mut();
    static mut BASE_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_base_construct(this: *mut u8) -> *mut u8 {
        unsafe {
            addr_of_mut!(BASE_INPUT).write(this);
            this.cast::<u32>().write_volatile(0xfeed_beef);
            BASE_RETURN
        }
    }

    #[test]
    fn constructs_base_then_replaces_its_vtable_word() {
        let _guard = LOCK.lock();
        let mut object = [0x1111_1111u32, 0x2222_2222];
        unsafe {
            addr_of_mut!(BASE_INPUT).write(core::ptr::null_mut());
            addr_of_mut!(BASE_RETURN).write(object.as_mut_ptr().cast());
            addr_of_mut!(OPAQUE_BASE_CONSTRUCT).write(recording_base_construct);
            let returned = opaque_vtable_089a8b14_construct(object.as_mut_ptr().cast());
            assert_eq!(addr_of!(BASE_INPUT).read(), object.as_mut_ptr().cast());
            assert_eq!(returned, object.as_mut_ptr().cast());
            assert_eq!(object[0], OPAQUE_VTABLE_089A8B14);
            assert_eq!(object[1], 0x2222_2222);
        }
    }

    #[test]
    fn overwrites_the_base_constructor_returned_object_not_the_input() {
        let _guard = LOCK.lock();
        let mut input = [0x1111_1111u32];
        let mut returned_object = [0x2222_2222u32];
        unsafe {
            addr_of_mut!(BASE_INPUT).write(core::ptr::null_mut());
            addr_of_mut!(BASE_RETURN).write(returned_object.as_mut_ptr().cast());
            addr_of_mut!(OPAQUE_BASE_CONSTRUCT).write(recording_base_construct);
            let returned = opaque_vtable_089a8b14_construct(input.as_mut_ptr().cast());
            assert_eq!(addr_of!(BASE_INPUT).read(), input.as_mut_ptr().cast());
            assert_eq!(returned, returned_object.as_mut_ptr().cast());
            assert_eq!(input[0], 0xfeed_beef);
            assert_eq!(returned_object[0], OPAQUE_VTABLE_089A8B14);
        }
    }
}
