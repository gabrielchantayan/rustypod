//! Demo-mode bounded string refresh — FUN_081a41c8 @ 0x081a41c8.
//! True size: 72 bytes; next function begins at 0x081a4210. Raw A32 has
//! three outbound plain BLs, no predicated BLs, and a final B to
//! string_object_resize_payload. Whole-image scan: two incoming plain BLs
//! (0x081a49b0, 0x081a4b0c), zero predicated BLs.
//!
//! Obtain TCDemoMode; if absent, leave the string untouched. Otherwise ensure
//! at least 40 bytes, call resident 0x08187d98 with the singleton, source,
//! current payload and bound 40, then resize to the resulting inclusive
//! C-string length. The resident writer's identity remains unresolved.
//! Deviations: native-width StringObject fields on hosts; explicit host-only
//! dependency injection. The unused incoming owner is retained for ABI parity.
//! Existing registry/capacity helpers retain their documented limitations.

use crate::app::registry::demo_mode_instance;
use crate::cxx::string_object::{StringObject, string_object_ensure_capacity,
    string_object_resize_payload};

type Writer = unsafe extern "C" fn(*mut u8, *const u8, *mut u8, u32);
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_writer(_: *mut u8, _: *const u8, _: *mut u8, _: u32) {
    panic!("demo_mode_string_refresh requires resident writer 0x08187d98")
}
#[cfg(not(target_os = "none"))]
pub static mut DEMO_MODE_STRING_INSTANCE: unsafe extern "C" fn() -> *mut u8 = demo_mode_instance;
#[cfg(not(target_os = "none"))]
pub static mut DEMO_MODE_STRING_WRITER: Writer = missing_writer;

/// Refresh a string through the demo-mode resident bounded writer.
/// # Safety
/// A present singleton requires a valid source accepted by resident 0x08187d98,
/// a valid StringObject and allocation slot, and a NUL-terminated writer result.
/// The resident writer must respect the 40-byte bound. No allocation NULL guard
/// is added: stock passes the observed payload directly to the writer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn demo_mode_string_refresh(
    _owner: *mut u8, source: *const u8, string: *mut StringObject,
) {
    #[cfg(target_os = "none")]
    let instance = demo_mode_instance;
    #[cfg(not(target_os = "none"))]
    let instance = DEMO_MODE_STRING_INSTANCE;
    let demo = instance();
    if demo.is_null() { return; }
    let payload = string_object_ensure_capacity(string, 40);
    #[cfg(target_os = "none")]
    let writer: Writer = core::mem::transmute(0x0818_7d98usize);
    #[cfg(not(target_os = "none"))]
    let writer = DEMO_MODE_STRING_WRITER;
    writer(demo, source, payload, 40);
    string_object_resize_payload(string, 0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::StringObjectVtable;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    #[repr(C)]
    struct Fixture { string: StringObject, resized: usize, preserve: u32 }
    unsafe extern "C" fn absent() -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn present() -> *mut u8 { core::ptr::dangling_mut::<u8>() }
    unsafe extern "C" fn write(_: *mut u8, source: *const u8, out: *mut u8, bound: u32) {
        let mut i = 0;
        while i + 1 < bound as usize && source.add(i).read() != 0 {
            out.add(i).write(source.add(i).read()); i += 1;
        }
        out.add(i).write(0);
    }
    unsafe extern "C" fn resize(p: *mut StringObject, size: usize, preserve: u32) -> *mut u8 {
        let f = &mut *p.cast::<Fixture>();
        f.resized = size; f.preserve = preserve; f.string.payload
    }
    #[test]
    fn absent_singleton_does_not_access_arguments() {
        let _lock = LOCK.lock();
        unsafe {
            DEMO_MODE_STRING_INSTANCE = absent;
            demo_mode_string_refresh(core::ptr::null_mut(), core::ptr::null(), core::ptr::null_mut());
            DEMO_MODE_STRING_INSTANCE = demo_mode_instance;
        }
    }
    #[test]
    fn writer_result_controls_resize_including_empty_and_bound() {
        let _lock = LOCK.lock();
        let table = StringObjectVtable { slots: [0, 0, resize as *const () as usize, 0, 0, 0] };
        unsafe {
            DEMO_MODE_STRING_INSTANCE = present;
            DEMO_MODE_STRING_WRITER = write;
            for length in [0, 1, 38, 39, 40, 63] {
                let mut source = [b'x'; 65]; source[length] = 0;
                // Inclusive length 41 avoids capacity allocation; the real
                // resize helper must measure the rewritten payload, not this.
                let mut payload = [b'z'; 64]; payload[40] = 0;
                let mut f = Fixture { string: StringObject { vtable: &table,
                    payload: payload.as_mut_ptr() }, resized: 0, preserve: 0 };
                demo_mode_string_refresh(core::ptr::null_mut(), source.as_ptr(), &mut f.string);
                let written = length.min(39);
                assert_eq!(&payload[..written], &source[..written]);
                assert_eq!(payload[written], 0);
                assert_eq!(f.resized, written + 1);
                assert_eq!(f.preserve, 1);
                assert_eq!(payload[41], b'z');
            }
            DEMO_MODE_STRING_INSTANCE = demo_mode_instance;
            DEMO_MODE_STRING_WRITER = missing_writer;
        }
    }
}
