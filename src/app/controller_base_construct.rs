//! RetailOS controller base constructor.
//!
//! `controller_base_construct` is `FUN_0810e2e4` at `0x0810e2e4`: **148
//! bytes** of code (`0x0810e2e4..0x0810e378`), ending at the following
//! separately addressed string literal. Decoding the raw ARM words finds
//! **4 plain unconditional `bl` instructions and 0 predicated `bl`**:
//! the opaque base constructor at `0x0812d074`, two string constructions,
//! and `observable_array_construct`.
//!
//! The constructor initializes its opaque inherited prefix, installs vtable
//! `0x0898d658`, builds three adjacent string members at target offsets
//! `+0x28`, `+0x30`, and `+0x38`, initializes scalar state through `+0x5c`,
//! and constructs an observable array at `+0x60`. The first string receives
//! the caller's name; the other two receive the ROM literals
//! `"CntrlPrePushFn"` and `"CntrlCntrlPrePopFn"`. It returns the base
//! constructor's returned object pointer after the final array construction.
//!
//! Deliberate host deviation: target strings are eight-byte objects but host
//! pointers are wider. Host tests therefore inject the three string calls;
//! target builds call the ported string constructor directly.

use crate::cxx::observable_array::{observable_array_construct, ObservableArray};
use crate::cxx::string_object::{string_object_construct_from_cstr, StringObject};

pub const CONTROLLER_BASE_VTABLE: u32 = 0x0898_d658;
pub const CONTROLLER_BASE_CONSTRUCT_ADDRESS: usize = 0x0812_d074;
const PRE_PUSH_NAME: &[u8] = b"CntrlPrePushFn\0";
const PRE_POP_NAME: &[u8] = b"CntrlCntrlPrePopFn\0";

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_controller_prefix_construct(this: *mut u8) -> *mut u8 {
    unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8) -> *mut u8>(CONTROLLER_BASE_CONSTRUCT_ADDRESS)(this) }
}

#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn missing_controller_prefix_construct(this: *mut u8) -> *mut u8 { this }

#[cfg(target_os = "none")]
pub static mut CONTROLLER_PREFIX_CONSTRUCT: unsafe extern "C" fn(*mut u8) -> *mut u8 =
    firmware_controller_prefix_construct;

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_PREFIX_CONSTRUCT: unsafe extern "C" fn(*mut u8) -> *mut u8 =
    missing_controller_prefix_construct;

#[cfg(not(target_os = "none"))]
pub static mut CONTROLLER_STRING_CONSTRUCT: unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8 =
    missing_controller_string_construct;

#[cfg(not(target_os = "none"))]
pub(crate) unsafe extern "C" fn missing_controller_string_construct(this: *mut u8, _source: *const u8) -> *mut u8 { this }
#[inline(always)]
unsafe fn write_word(this: *mut u8, offset: usize, value: u32) {
    unsafe { this.add(offset).cast::<u32>().write_volatile(value) }
}

#[inline(always)]
unsafe fn write_byte(this: *mut u8, offset: usize, value: u8) {
    unsafe { this.add(offset).write_volatile(value) }
}

/// `controller_base_construct` — `FUN_0810e2e4` @ `0x0810e2e4` (148 bytes;
/// 4 unconditional plain `bl`, 0 predicated `bl`, raw-word verified).
///
/// # Safety
/// `this` must name at least 0x70 writable, four-byte-aligned target-layout
/// bytes; `name` is a NUL-terminated C string. The inherited constructor's
/// returned pointer must name that same layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn controller_base_construct(this: *mut u8, name: *const u8) -> *mut u8 {
    unsafe {
        let base = (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_PREFIX_CONSTRUCT)))(this);
        write_word(base, 0, CONTROLLER_BASE_VTABLE);
        #[cfg(target_os = "none")]
        let first = string_object_construct_from_cstr(base.add(0x28).cast::<StringObject>(), name).cast::<u8>();
        #[cfg(not(target_os = "none"))]
        let first = (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_STRING_CONSTRUCT)))(base.add(0x28), name);
        #[cfg(target_os = "none")]
        let second = string_object_construct_from_cstr(first.add(8).cast::<StringObject>(), PRE_PUSH_NAME.as_ptr()).cast::<u8>();
        #[cfg(not(target_os = "none"))]
        let second = (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_STRING_CONSTRUCT)))(first.add(8), PRE_PUSH_NAME.as_ptr());
        #[cfg(target_os = "none")]
        let third = string_object_construct_from_cstr(second.add(8).cast::<StringObject>(), PRE_POP_NAME.as_ptr()).cast::<u8>();
        #[cfg(not(target_os = "none"))]
        let third = (core::ptr::read_volatile(core::ptr::addr_of!(CONTROLLER_STRING_CONSTRUCT)))(second.add(8), PRE_POP_NAME.as_ptr());
        let base = third.sub(0x38);
        write_byte(base, 0x40, 0); write_byte(base, 0x41, 0); write_word(base, 0x44, 0);
        write_byte(base, 0x48, 1); write_word(base, 0x4c, 1); write_word(base, 0x50, 0);
        write_word(base, 0x54, 0); write_word(base, 0x58, 0); write_word(base, 0x5c, u32::MAX);
        let array = observable_array_construct(base.add(0x60).cast::<ObservableArray>()).cast::<u8>();
        write_word(array, 0, 0x0898_d65c); write_byte(array, 0x10, 1); write_word(array, 0x14, 0);
        array.sub(0x60)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, usize); 3] = [(0, 0); 3];
    static mut COUNT: usize = 0;
    unsafe extern "C" fn strings(this: *mut u8, source: *const u8) -> *mut u8 {
        unsafe { CALLS[COUNT] = (this as usize, source as usize); COUNT += 1; this }
    }
    #[test]
    fn initializes_target_offsets_and_constructs_strings_in_order() {
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let mut bytes = [0xa5u8; 0x80];
        unsafe {
            COUNT = 0; CONTROLLER_PREFIX_CONSTRUCT = missing_controller_prefix_construct; CONTROLLER_STRING_CONSTRUCT = strings;
            let result = controller_base_construct(bytes.as_mut_ptr(), c"name".as_ptr().cast());
            assert_eq!(result, bytes.as_mut_ptr()); assert_eq!(COUNT, 3);
            assert_eq!(CALLS[0].0 - bytes.as_ptr() as usize, 0x28); assert_eq!(CALLS[1].0 - bytes.as_ptr() as usize, 0x30); assert_eq!(CALLS[2].0 - bytes.as_ptr() as usize, 0x38);
            assert_eq!((bytes.as_ptr().add(0x40)).read(), 0); assert_eq!((bytes.as_ptr().add(0x48)).read(), 1);
            assert_eq!((bytes.as_ptr().add(0x5c).cast::<u32>()).read_unaligned(), u32::MAX);
            assert_eq!((bytes.as_ptr().add(0x60).cast::<u32>()).read_unaligned(), 0x0898_d65c);
        }
    }
}
