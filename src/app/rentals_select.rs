//! Rentals selection — `FUN_0822f280` @ **0x0822f280**.
//! True extent **220 bytes**, 0x0822f280..0x0822f35c: 188 code bytes,
//! four literal words and the padded RentalsSelected string. Raw words show
//! eight plain BLs, zero predicated BLs and one virtual BLX in the body;
//! inbound calls are one plain BL and one BLNE (two total).
//!
//! Sets controller +0xb0 to 19 and requests the cached query with
//! (0x80, 0x200004, 1, 1, 0, 1). Only for a nonzero result, loads screen
//! layout resource 0x0dad0695 from class 0x80, sets decimal 1 under the
//! runtime key at 0x089cfe5c in table 0x08a79c10, then displays
//! RentalsSelected through vtable +0x11c. Releases both temporary strings
//! and returns 1 even when the query is empty.
//!
//! Deviations: omit the unused third COW constructor argument. Host vtables
//! use native-width words with target word indices. Host-only operations
//! replace device globals/dependencies; target uses existing Rust ports and
//! the verified unported cached-query seam, never guessed callee identities.

use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};
use super::music_menu_playlist_select::controller_cached_query;
use super::singletons::app_screen_get;
use super::screen_layout::app_screen_set_layout_from_resource;
use super::string_table::string_table_set_decimal;

type CachedQuery = unsafe extern "C" fn(*mut u8, u32, u32, u32, u32, u32, u32) -> u32;
#[derive(Clone, Copy)]
pub struct RentalsSelectOps {
    pub cached_query: CachedQuery,
    pub screen_get: unsafe extern "C" fn() -> *mut u8,
    pub layout: unsafe extern "C" fn(*mut u8, u32, u32),
    pub key: unsafe extern "C" fn() -> *const u8,
    pub string_create: unsafe extern "C" fn(*mut *mut u8, *const u8) -> *mut *mut u8,
    pub string_release: unsafe extern "C" fn(*mut *mut u8),
    pub decimal: unsafe extern "C" fn(*mut u8, *mut *mut u8, *const i32),
}
unsafe extern "C" fn rentals_key() -> *const u8 {
    #[cfg(target_os = "none")]
    return (0x089c_fe5cusize as *const *const u8).read();
    #[cfg(not(target_os = "none"))]
    panic!("rentals runtime key requires host dependency injection")
}
const DEFAULT_OPS: RentalsSelectOps = RentalsSelectOps {
    cached_query: controller_cached_query, screen_get: app_screen_get,
    layout: app_screen_set_layout_from_resource, key: rentals_key,
    string_create: cxx_string_from_cstr, string_release: cxx_string_release,
    decimal: string_table_set_decimal,
};
#[cfg(not(target_os = "none"))]
pub static mut RENTALS_SELECT_OPS: RentalsSelectOps = DEFAULT_OPS;

unsafe fn select(controller: *mut u8, ops: RentalsSelectOps) -> u32 {
    controller.add(0xb0).write(19);
    if (ops.cached_query)(controller, 0x80, 0x200004, 1, 1, 0, 1) != 0 {
        (ops.layout)((ops.screen_get)(), 0x80, 0x0dad0695);
        let mut string = core::ptr::null_mut();
        let key = (ops.string_create)(&mut string, (ops.key)());
        (ops.decimal)(0x08a7_9c10 as *mut u8, key, &1);
        (ops.string_release)(&mut string);
        let command = (ops.string_create)(&mut string, b"RentalsSelected\0".as_ptr());
        let vtable = (controller as *const *const usize).read();
        let display: unsafe extern "C" fn(*mut u8, *mut *mut u8) =
            core::mem::transmute(vtable.add(0x11c / 4).read());
        display(controller, command);
        (ops.string_release)(&mut string);
    }
    1
}

/// Select rentals and, when available, update the layout and display command.
/// # Safety
/// Controller must be writable through +0xb0 and have a valid +0x11c method.
/// Dependencies and the runtime key/table must satisfy their port contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn rentals_select(controller: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let ops = DEFAULT_OPS;
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(RENTALS_SELECT_OPS));
    select(controller, ops)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::ffi::CStr;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut COUNT: u32 = 0;
    static mut EVENTS: std::vec::Vec<&'static str> = std::vec::Vec::new();
    unsafe extern "C" fn query(c: *mut u8, a: u32, b: u32, r: u32, k: u32, f: u32, o: u32) -> u32 {
        assert_eq!(c.add(0xb0).read(), 19);
        assert_eq!((a,b,r,k,f,o), (0x80,0x200004,1,1,0,1));
        COUNT
    }
    unsafe extern "C" fn screen() -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn layout(_: *mut u8, _: u32, _: u32) { EVENTS.push("layout"); }
    unsafe extern "C" fn key() -> *const u8 { b"runtime-key\0".as_ptr() }
    unsafe extern "C" fn create(s: *mut *mut u8, p: *const u8) -> *mut *mut u8 { s.write(p as *mut u8); s }
    unsafe extern "C" fn release(_: *mut *mut u8) { EVENTS.push("release"); }
    unsafe extern "C" fn decimal(_: *mut u8, key: *mut *mut u8, value: *const i32) {
        assert_eq!(CStr::from_ptr(key.read().cast()).to_bytes(), b"runtime-key");
        assert_eq!(value.read(), 1);
        EVENTS.push("decimal");
    }
    unsafe extern "C" fn display(_: *mut u8, command: *mut *mut u8) {
        assert_eq!(CStr::from_ptr(command.read().cast()).to_bytes(), b"RentalsSelected");
        EVENTS.push("display");
    }
    #[test]
    fn empty_suppresses_ui_and_every_nonzero_result_commits_in_order() {
        let _lock = LOCK.lock();
        let mut vtable = [0usize; 0x11c / 4 + 1];
        vtable[0x11c / 4] = display as *const () as usize;
        let mut controller = [usize::from_ne_bytes([0xa5; core::mem::size_of::<usize>()]); 0xc8 / core::mem::size_of::<usize>()];
        controller[0] = vtable.as_ptr() as usize;
        let c = controller.as_mut_ptr().cast::<u8>();
        unsafe {
            for count in [0, 1, 0x80000000, u32::MAX, 0] {
                COUNT = count; EVENTS.clear();
                assert_eq!(select(c, RentalsSelectOps { cached_query: query, screen_get: screen,
                    layout, key, string_create: create, string_release: release, decimal }), 1);
                let expected: &[&str] = if count == 0 { &[] } else {
                    &["layout", "decimal", "release", "display", "release"]
                };
                assert_eq!(EVENTS.as_slice(), expected);
                assert_eq!(c.add(0xaf).read(), 0xa5);
                assert_eq!(c.add(0xb1).read(), 0xa5);
            }
        }
    }
}
