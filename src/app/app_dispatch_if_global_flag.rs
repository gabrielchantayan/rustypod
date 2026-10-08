//! `app_dispatch_if_global_flag` — `FUN_08114d30` @ **0x08114d30**.
//! True extent: **56 bytes**, [0x08114d30, 0x08114d68): 44 instruction
//! bytes and three literal words; the next function starts with push at
//! 0x08114d68. Whole-image A32 decoding finds two inbound plain BLs
//! (0x0811624c, 0x0819e304), zero predicated BLs. The body has zero plain
//! or predicated BLs and one predicated indirect BLX through slot +0x58.
//!
//! Read the global byte at 0x089caf4b. If nonzero, dispatch (Str , 0x6406)
//! through the receiver's vtable slot +0x58, ignoring its result. Reload
//! and return the zero-extended global byte, including callback changes.
//! Neither the flag's higher-level meaning nor the virtual callee's identity
//! is established; no direct callee seam is invented.
//!
//! Deliberate deviations: hosts substitute writable storage for the fixed
//! global address and use native-width vtable words at the same word index.

use core::ptr;

/// Host substitute for the firmware byte; callers must serialize mutations.
#[cfg(not(target_os = "none"))]
pub static mut CONDITIONAL_APP_COMMAND_FLAG: u8 = 0;

#[inline(always)]
unsafe fn flag_address() -> *mut u8 {
    #[cfg(target_os = "none")]
    { 0x089c_af4busize as *mut u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of_mut!(CONDITIONAL_APP_COMMAND_FLAG) }
}

/// Dispatches resource 0x6406 when the shared byte is nonzero, then reloads it.
///
/// # Safety
/// When the flag is nonzero, `receiver` must have a valid vtable whose word
/// index 22 is callable as `(receiver, u32, u32)`. The global byte must be
/// readable; host access must be serialized. A zero flag permits a NULL receiver.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_dispatch_if_global_flag(receiver: *mut u8) -> u32 {
    let flag = flag_address();
    if ptr::read_volatile(flag) != 0 {
        let vtable = ptr::read_volatile(receiver.cast::<*const usize>());
        let dispatch: unsafe extern "C" fn(*mut u8, u32, u32) =
            core::mem::transmute(ptr::read_volatile(vtable.add(0x58 / 4)));
        dispatch(receiver, 0x5374_7220, 0x6406);
    }
    u32::from(ptr::read_volatile(flag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Receiver {
        vtable: *const usize,
        calls: u32,
        replacement: u8,
        category: u32,
        resource: u32,
    }

    unsafe extern "C" fn update_flag(receiver: *mut u8, category: u32, resource: u32) {
        let receiver = &mut *receiver.cast::<Receiver>();
        receiver.calls += 1;
        receiver.category = category;
        receiver.resource = resource;
        ptr::write_volatile(flag_address(), receiver.replacement);
    }

    #[test]
    fn zero_skips_receiver_and_nonzero_returns_callback_updated_byte() {
        unsafe {
            let old = ptr::read_volatile(flag_address());
            ptr::write_volatile(flag_address(), 0);
            assert_eq!(app_dispatch_if_global_flag(ptr::null_mut()), 0);
            let mut vtable = [0usize; 23];
            vtable[22] = update_flag as *const () as usize;
            for initial in [1, 0x7f, 0x80, 0xff] {
                for replacement in [0, 1, 0x80, 0xff] {
                    let mut receiver = Receiver {
                        vtable: vtable.as_ptr(), calls: 0, replacement,
                        category: 0, resource: 0,
                    };
                    ptr::write_volatile(flag_address(), initial);
                    let result = app_dispatch_if_global_flag((&mut receiver as *mut Receiver).cast());
                    assert_eq!(result, u32::from(replacement));
                    assert_eq!(receiver.calls, 1);
                    assert_eq!((receiver.category, receiver.resource), (0x5374_7220, 0x6406));
                }
            }
            ptr::write_volatile(flag_address(), old);
        }
    }
}
