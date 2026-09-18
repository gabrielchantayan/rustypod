//! Construct a StringObject from an opaque object's rendered C string.
//!
//! [`object_string_construct`] — original: `FUN_0810704c` @ `0x0810704c`
//! (80 bytes, `0x0810704c..0x0810709c`; **3 plain `bl` calls, 0 predicated**).
//!
//! The function initializes the two-word StringObject with the base vtable
//! literal `0x089a6044` and a NULL payload. It asks the unported renderer at
//! `0x0805235c` to write at most 254 characters plus a NUL into a 256-byte
//! stack buffer. On a zero result it assigns that buffer to the StringObject
//! and normalizes the resulting text in place through `FUN_08276db4`.
//!
//! Deliberate deviations: the renderer and normalizer remain explicit seams;
//! their target defaults call the original addresses, while the host renderer
//! fails with the original invalid-argument result. The vtable is represented
//! by the existing host identity static rather than the ROM address.

use core::mem::MaybeUninit;
use core::ptr;

use crate::cxx::path_escape_record::STRING_OBJECT_TEXT_NORMALIZE;
use crate::cxx::string_object::{
    string_object_assign_payload, StringObject, STRING_OBJECT_VTABLE,
};

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_object_render_cstr(
    object: *mut u8, output: *mut u8, capacity: u32,
) -> i32 {
    let call: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32 =
        core::mem::transmute(0x0805_235cusize);
    call(object, output, capacity)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_object_render_cstr(
    _object: *mut u8, _output: *mut u8, _capacity: u32,
) -> i32 {
    -0x32
}

/// Unported `FUN_0805235c` boundary: render an opaque object into a bounded,
/// NUL-terminated C-string buffer. A zero result permits assignment.
#[cfg(target_os = "none")]
pub static mut OBJECT_RENDER_CSTR: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32 =
    firmware_object_render_cstr;
#[cfg(not(target_os = "none"))]
pub static mut OBJECT_RENDER_CSTR: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32 =
    missing_object_render_cstr;

#[inline(always)]
unsafe fn object_render_cstr_op() -> unsafe extern "C" fn(*mut u8, *mut u8, u32) -> i32 {
    ptr::read_volatile(ptr::addr_of!(OBJECT_RENDER_CSTR))
}

/// Constructs a base StringObject from the rendered text of `*object_reference`.
///
/// The source reference is dereferenced before the renderer call, exactly as
/// the ARM `ldr r0, [r1]`; neither pointer is NULL-guarded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_string_construct(
    this: *mut StringObject,
    object_reference: *const *mut u8,
) {
    (*this).vtable = ptr::addr_of!(STRING_OBJECT_VTABLE);
    (*this).payload = ptr::null_mut();

    let mut rendered = MaybeUninit::<[u8; 256]>::uninit();
    let rendered_ptr = rendered.as_mut_ptr().cast::<u8>();
    if object_render_cstr_op()(*object_reference, rendered_ptr, 0xff) == 0 {
        string_object_assign_payload(this, rendered_ptr);
        ptr::read_volatile(ptr::addr_of!(STRING_OBJECT_TEXT_NORMALIZE))(this);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: Option<(usize, u32)> = None;

    unsafe extern "C" fn render_one_character(
        object: *mut u8, output: *mut u8, capacity: u32,
    ) -> i32 {
        CALL = Some((object as usize, capacity));
        output.write(b'x');
        output.add(1).write(0);
        0
    }

    #[test]
    fn renderer_failure_leaves_a_initialized_empty_string() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut string = StringObject { vtable: ptr::null(), payload: 1usize as *mut u8 };
        let mut object = 0u8;
        let reference = ptr::addr_of_mut!(object);

        unsafe { object_string_construct(ptr::addr_of_mut!(string), ptr::addr_of!(reference)); }

        assert_eq!(string.vtable, ptr::addr_of!(STRING_OBJECT_VTABLE));
        assert!(string.payload.is_null());
    }

    #[test]
    fn successful_render_uses_the_referenced_object_and_255_byte_limit() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut string = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
        let mut object = 0u8;
        let reference = ptr::addr_of_mut!(object);
        unsafe {
            CALL = None;
            OBJECT_RENDER_CSTR = render_one_character;
            object_string_construct(ptr::addr_of_mut!(string), ptr::addr_of!(reference));
            OBJECT_RENDER_CSTR = missing_object_render_cstr;
        }

        assert_eq!(unsafe { CALL }, Some((ptr::addr_of_mut!(object) as usize, 0xff)));
        assert_eq!(string.vtable, ptr::addr_of!(STRING_OBJECT_VTABLE));
        assert!(string.payload.is_null(), "the default allocation seam fails closed");
    }
}
