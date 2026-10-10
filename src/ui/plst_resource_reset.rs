//! 'plst' element resource reset.

use core::ptr;
use crate::app::resource::cache::resource_callback_dispatch;
use super::plst_class_check::ui_element_is_plst_class;

const RESOURCE_WORD: usize = 0x40 / 4;
const RESULT_WORD: usize = 0x14 / 4;
const RESOURCE_CALLBACK: usize = 0x080c_c284;

pub type PlstResourceResetDispatch = unsafe extern "C" fn(*mut u8, usize, *mut u8) -> i32;
/// Dispatcher seam; the callback remains the verified firmware entry address.
pub static mut PLST_RESOURCE_RESET_DISPATCH: PlstResourceResetDispatch = resource_callback_dispatch;

/// plst_resource_reset — original: `FUN_0806c16c` @ `0x0806c16c`.
/// True extent: 56 bytes to the next prologue at `0x0806c1a4`: 52 bytes of
/// instructions and the callback literal at `0x0806c1a0`. Verified outbound
/// calls: two plain BLs, zero predicated BLs. Inbound: two plain BLs at
/// `0x08048224` and `0x0806c1dc`, zero predicated BLs.
///
/// Reject NULL/non-'plst' elements. Otherwise dispatch the resource at +0x40
/// with callback `0x080cc284` and NULL context, ignore its status, reload +0x40,
/// and clear that resource's +0x14 word even if dispatch failed or changed it.
/// Deliberate deviations: use the ported class predicate and dispatcher; a
/// volatile dispatcher seam permits host execution without calling ARM code.
/// No semantic identity is assigned to the callback literal.
///
/// # Safety
/// A non-NULL element must be aligned and readable through +7. A 'plst'
/// element must additionally be writable/readable through +0x43 and supply
/// a valid resource tree for dispatch. Its reloaded resource pointer must be
/// non-NULL, aligned, and writable through +0x17, including after a failed call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_resource_reset(element: *mut u32) {
    if ui_element_is_plst_class(element.cast()) == 0 {
        return;
    }
    let resource = element.add(RESOURCE_WORD).read() as usize as *mut u8;
    let dispatch = ptr::read_volatile(ptr::addr_of!(PLST_RESOURCE_RESET_DISPATCH));
    dispatch(resource, RESOURCE_CALLBACK, ptr::null_mut());
    let resource = element.add(RESOURCE_WORD).read() as usize as *mut u32;
    resource.add(RESULT_WORD).write(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ELEMENT: *mut u32 = ptr::null_mut();
    static mut REPLACEMENT: *mut u32 = ptr::null_mut();
    static mut STATUS: i32 = 0;
    static mut CALLS: usize = 0;

    unsafe extern "C" fn dispatch(root: *mut u8, callback: usize, context: *mut u8) -> i32 {
        assert_eq!(callback, RESOURCE_CALLBACK);
        assert!(context.is_null());
        assert_eq!(root as usize, ELEMENT.add(RESOURCE_WORD).read() as usize);
        assert_eq!(root.cast::<u32>().add(RESULT_WORD).read(), 0x1234);
        CALLS += 1;
        if !REPLACEMENT.is_null() {
            ELEMENT.add(RESOURCE_WORD).write(REPLACEMENT as usize as u32);
        }
        STATUS
    }

    struct Restore(PlstResourceResetDispatch);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { PLST_RESOURCE_RESET_DISPATCH = self.0; } }
    }

    #[test]
    fn rejects_invalid_class_and_reloads_resource_even_after_dispatch_failure() {
        let _lock = LOCK.lock();
        let base = try_map_u32_slab(hints::PLST_RESOURCE_RESET, 0x1000)
            .expect("target-width resource-reset fixture");
        unsafe {
            let _restore = Restore(PLST_RESOURCE_RESET_DISPATCH);
            PLST_RESOURCE_RESET_DISPATCH = dispatch;
            CALLS = 0;
            // An invalid object need only contain its class tag, not +0x40.
            let mut invalid = [0u32, 0x7464_6174];
            plst_resource_reset(ptr::null_mut());
            plst_resource_reset(invalid.as_mut_ptr());
            assert_eq!(CALLS, 0);
            base.write_bytes(0, 0x1000);
            ELEMENT = base.cast();
            let original = base.add(0x100).cast::<u32>();
            let replacement = base.add(0x200).cast::<u32>();
            ELEMENT.add(1).write(0x706c_7374);
            for status in [0, -50, 7] {
                for replace in [false, true] {
                    ELEMENT.add(RESOURCE_WORD).write(original as usize as u32);
                    original.add(RESULT_WORD - 1).write(0xaaaa);
                    original.add(RESULT_WORD).write(0x1234);
                    original.add(RESULT_WORD + 1).write(0xbbbb);
                    replacement.add(RESULT_WORD).write(0x5678);
                    REPLACEMENT = if replace { replacement } else { ptr::null_mut() };
                    STATUS = status;
                    plst_resource_reset(ELEMENT);
                    assert_eq!(original.add(RESULT_WORD).read(), if replace { 0x1234 } else { 0 });
                    assert_eq!(replacement.add(RESULT_WORD).read(), if replace { 0 } else { 0x5678 });
                    assert_eq!(original.add(RESULT_WORD - 1).read(), 0xaaaa);
                    assert_eq!(original.add(RESULT_WORD + 1).read(), 0xbbbb);
                }
            }
            assert_eq!(CALLS, 6);
        }
    }
}
