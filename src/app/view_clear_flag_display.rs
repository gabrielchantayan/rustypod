//! Clear the view's +0xb1 flag, stop its optional timer, and display a literal.
//!
//! `view_clear_flag_display` — `FUN_08158f38` @ 0x08158f38.
//! True extent 76 bytes, 0x08158f38..0x08158f84: 72 code bytes and
//! a four-byte literal before the next independent push. Raw A32 verifies
//! three plain outbound BLs, zero predicated BLs, one virtual BLX, and two
//! plain inbound BLs (0x081590ac, 0x0815911c), zero predicated inbound BLs.
//! Writes zero to +0xb1, calls stop_view_timer, constructs a temporary COW
//! string from 0x083eb638, dispatches vtable +0x11c, then releases the string.
//! Deliberate deviations: omit unused r1/r2/r3 inputs and allocator-tag stack
//! residue, as in the existing COW-string port. Native-width host vtable
//! entries use word index 71; firmware entries are four bytes. The target
//! preserves the literal address: raw bytes there resemble instructions,
//! not readable text, so no speculative message identity is assigned.

use crate::app::view_event::stop_view_timer;
use crate::cxx::string::{cxx_string_from_cstr, cxx_string_release};

#[cfg(not(target_os = "none"))]
const SOURCE: &[u8] = b"\x06\x60\xa6\xe0\x05\x80\x50\xe0\x04\xc0\xd1\xe0\0";

/// # Safety
/// `view` must be writable through +0xb1, contain the target-width optional
/// timer word at +0x50, and have a valid vtable with a display method at
/// word 71. Display may copy the string but must not retain its stack slot.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_clear_flag_display(view: *mut u8) {
    unsafe {
        view.add(0xb1).write(0);
        stop_view_timer(view);
        #[cfg(target_os = "none")]
        let source = 0x083e_b638usize as *const u8;
        #[cfg(not(target_os = "none"))]
        let source = SOURCE.as_ptr();
        let mut message = core::ptr::null_mut();
        let slot = cxx_string_from_cstr(&mut message, source);
        let vtable = view.cast::<*const usize>().read();
        let display: unsafe extern "C" fn(*mut u8, *mut *mut u8) =
            core::mem::transmute(vtable.add(71).read());
        display(view, slot);
        cxx_string_release(&mut message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string::{cxx_string_copy_ctor, StringRep};
    use crate::heap::veneers::tests::{mock_heap, set_alloc_ret, free_log};

    #[repr(C)]
    struct Fixture {
        view: [usize; 24],
        retain: bool,
        retained: *mut u8,
    }

    unsafe extern "C" fn display(view: *mut u8, slot: *mut *mut u8) {
        unsafe {
            let fixture = &mut *view.cast::<Fixture>();
            assert_eq!(view.add(0xb1).read(), 0);
            assert_eq!(core::slice::from_raw_parts(*slot, SOURCE.len()), SOURCE);
            assert_eq!(free_log().0, 0);
            if fixture.retain { cxx_string_copy_ctor(&mut fixture.retained, slot); }
            view.add(0xb1).write(0x7f);
        }
    }

    #[test]
    fn absent_timer_and_display_string_ownership() {
        for retain in [false, true] {
            let _heap = mock_heap();
            let mut vtable = [0usize; 72];
            vtable[71] = display as *const () as usize;
            let mut fixture = Fixture {
                view: [0; 24], retain, retained: core::ptr::null_mut(),
            };
            let mut allocation = [0u32; 16];
            unsafe {
                let view = fixture.view.as_mut_ptr().cast::<u8>();
                view.cast::<*const usize>().write(vtable.as_ptr());
                view.add(0xb0).write(0xa5);
                view.add(0xb1).write(0xff);
                view.add(0xb2).write(0x5a);
                let rep = allocation.as_mut_ptr().cast::<StringRep>();
                set_alloc_ret(rep.cast());
                view_clear_flag_display(view);
                assert_eq!(view.add(0xb0).read(), 0xa5);
                assert_eq!(view.add(0xb1).read(), 0x7f);
                assert_eq!(view.add(0xb2).read(), 0x5a);
                if retain {
                    assert_eq!((*rep).refcount, 0);
                    assert_eq!(free_log().0, 0);
                    assert_eq!(core::slice::from_raw_parts(fixture.retained, SOURCE.len()), SOURCE);
                    cxx_string_release(&mut fixture.retained);
                } else { assert_eq!((*rep).refcount, -1); }
                assert_eq!(free_log(), (1, rep.cast(), 2));
            }
        }
    }
}
