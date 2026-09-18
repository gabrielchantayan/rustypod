//! Class-0x6280 pending-state reset.
//!
//! `class_6280_clear_pending_and_post_resource` — `FUN_0811af38` @
//! 0x0811af38. The true extent is 36 bytes: seven ARM instruction words
//! (0x0811af38..0x0811af50) followed by two literal-pool words at
//! 0x0811af54 and 0x0811af58; the next independent function begins at
//! 0x0811af5c. Raw ARM decoding finds four inbound plain direct `bl` calls,
//! zero predicated direct `bl` calls, and no direct calls in this function.
//! It clears the view's pending byte at +0x68, then tail-dispatches vtable
//! slot +0x58 with opaque value `"warD"` (0x44726177) and resource 0x6289.
//!
//! Deliberate deviation: Rust performs an ordinary call and return where the
//! firmware tail-branches. The target uses the existing physical vtable
//! dispatch; host tests use its widened vtable adapter.

use core::ptr;

#[cfg(not(target_os = "none"))]
use crate::app::class_6280_set_position::dispatch_resource;

const PENDING_OFFSET: usize = 0x68;
const RESOURCE_VALUE: u32 = 0x4472_6177;
const RESOURCE_ID: u32 = 0x6289;

#[cfg(target_os = "none")]
unsafe fn dispatch_resource(view: *mut u8, value: u32, resource: u32) {
    let vtable = ptr::read_volatile(view.cast::<u32>()) as usize as *const u32;
    let address = ptr::read_volatile(vtable.add(0x58 / 4));
    let dispatch: unsafe extern "C" fn(*mut u8, u32, u32) = core::mem::transmute(address as usize);
    dispatch(view, value, resource);
}

/// Clears the class-0x6280 pending byte and posts its associated resource.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class_6280_clear_pending_and_post_resource(view: *mut u8) {
    ptr::write_volatile(view.add(PENDING_OFFSET), 0);
    dispatch_resource(view, RESOURCE_VALUE, RESOURCE_ID);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::class_6280_set_position::HostClass6280Vtable;
    use core::ptr::{addr_of, addr_of_mut};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut DISPATCHES: [(u32, u32); 2] = [(0, 0); 2];
    static mut DISPATCH_COUNT: usize = 0;

    unsafe extern "C" fn resource(_: *mut u8, value: u32, resource: u32) {
        DISPATCHES[DISPATCH_COUNT] = (value, resource);
        DISPATCH_COUNT += 1;
    }

    static VTABLE: HostClass6280Vtable = HostClass6280Vtable {
        _before_resource: [0; 11],
        resource,
    };

    #[repr(C, align(8))]
    struct View([u8; PENDING_OFFSET + 1]);

    fn view(pending: u8) -> View {
        let mut view = View([0; PENDING_OFFSET + 1]);
        unsafe {
            addr_of_mut!(view.0).cast::<*const HostClass6280Vtable>().write(addr_of!(VTABLE));
        }
        view.0[PENDING_OFFSET] = pending;
        view
    }

    #[test]
    fn clears_a_set_pending_byte_and_posts_the_expected_resource() {
        let _guard = LOCK.lock();
        unsafe { DISPATCHES = [(0, 0); 2]; DISPATCH_COUNT = 0; }
        let mut view = view(0xff);

        unsafe { class_6280_clear_pending_and_post_resource(view.0.as_mut_ptr()); }

        assert_eq!(view.0[PENDING_OFFSET], 0);
        unsafe {
            assert_eq!(DISPATCH_COUNT, 1);
            assert_eq!(DISPATCHES[0], (RESOURCE_VALUE, RESOURCE_ID));
        }
    }

    #[test]
    fn posts_the_resource_when_the_pending_byte_is_already_clear() {
        let _guard = LOCK.lock();
        unsafe { DISPATCHES = [(0, 0); 2]; DISPATCH_COUNT = 0; }
        let mut view = view(0);

        unsafe { class_6280_clear_pending_and_post_resource(view.0.as_mut_ptr()); }

        assert_eq!(view.0[PENDING_OFFSET], 0);
        unsafe { assert_eq!(DISPATCH_COUNT, 1); }
    }
}
