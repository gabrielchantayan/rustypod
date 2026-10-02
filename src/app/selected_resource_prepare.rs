//! Selected-resource preparation — `FUN_0828ace0` @ `0x0828ace0`.
//!
//! True size: 140 bytes (116 code, 24 literal pool); next function starts
//! at 0x0828ad6c. Raw aligned A32 decoding finds two inbound plain BLs
//! (0x0828a620, 0x0828b108), zero predicated BLs. Outbound: one plain BL
//! to 0x08119ed4, zero predicated BLs, and two virtual BLX sites.
//!
//! Stores the selected object at +0xdc. If nonzero and byte +0x5a8 is set,
//! calls retail 0x08119ed4 with that object, stores its result at +0x544,
//! dispatches (Draw, 0x4197), and rereads the result. A nonzero result then
//! dispatches (Str , 0x41a1) and returns 0x41a6; otherwise returns 0x41a7.
//! Deliberate deviations: host-only seams replace the unported helper and
//! target-width virtual pointer. Object words retain ARM offsets on hosts.
//! No callee subsystem identity is asserted; Ghidra omits its r0 argument.

use core::ptr;

type Resolve = unsafe extern "C" fn(*mut u8) -> u32;
type Dispatch = unsafe extern "C" fn(*mut u32, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_resolve(_: *mut u8) -> u32 {
    panic!("install SELECTED_RESOURCE_RESOLVE before host use");
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_dispatch(_: *mut u32, _: u32, _: u32) {
    panic!("install SELECTED_RESOURCE_DISPATCH before host use");
}
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_RESOURCE_RESOLVE: Resolve = missing_resolve;
#[cfg(not(target_os = "none"))]
pub static mut SELECTED_RESOURCE_DISPATCH: Dispatch = missing_dispatch;

#[inline(always)]
unsafe fn resolve(selected: u32) -> u32 {
    #[cfg(target_os = "none")]
    let call: Resolve = core::mem::transmute(0x0811_9ed4usize);
    #[cfg(not(target_os = "none"))]
    let call = ptr::read_volatile(ptr::addr_of!(SELECTED_RESOURCE_RESOLVE));
    call(selected as usize as *mut u8)
}

#[inline(always)]
unsafe fn dispatch(view: *mut u32, kind: u32, action: u32) {
    #[cfg(target_os = "none")]
    let call: Dispatch = {
        let vtable = ptr::read_volatile(view) as *const u32;
        core::mem::transmute(ptr::read_volatile(vtable.add(0x58 / 4)) as usize)
    };
    #[cfg(not(target_os = "none"))]
    let call = ptr::read_volatile(ptr::addr_of!(SELECTED_RESOURCE_DISPATCH));
    call(view, kind, action);
}

/// # Safety
/// `view` must be aligned writable object storage through byte +0x5a8.
/// On the active path, `selected` must be a valid retail object and the
/// view's vtable slot +0x58 must be callable. Host seams require exclusive
/// installation and must uphold those contracts.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn selected_resource_prepare(view: *mut u32, selected: u32) -> u32 {
    ptr::write(view.add(0xdc / 4), selected);
    if selected != 0 && ptr::read(view.cast::<u8>().add(0x5a8)) != 0 {
        ptr::write(view.add(0x544 / 4), resolve(selected));
        dispatch(view, 0x4472_6177, 0x4197);
        if ptr::read_volatile(view.add(0x544 / 4)) != 0 {
            dispatch(view, 0x5374_7220, 0x41a1);
            return 0x41a6;
        }
    }
    0x41a7
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut RESULT: u32 = 0;
    static mut REPLACEMENT: u32 = 0;
    static mut STEP: u32 = 0;

    unsafe extern "C" fn fixture_resolve(selected: *mut u8) -> u32 {
        assert_eq!(selected as usize, 0x1234);
        assert_eq!(STEP, 0);
        STEP = 1;
        RESULT
    }
    unsafe extern "C" fn fixture_dispatch(view: *mut u32, kind: u32, action: u32) {
        assert_eq!(*view.add(0xdc / 4), 0x1234);
        match STEP {
            1 => {
                assert_eq!((kind, action), (0x4472_6177, 0x4197));
                assert_eq!(*view.add(0x544 / 4), RESULT);
                *view.add(0x544 / 4) = REPLACEMENT;
                STEP = 2;
            }
            2 => {
                assert_ne!(*view.add(0x544 / 4), 0);
                assert_eq!((kind, action), (0x5374_7220, 0x41a1));
                STEP = 3;
            }
            _ => panic!("unexpected dispatch"),
        }
    }

    #[test]
    fn inactive_selection_updates_only_selected_word() {
        let _guard = LOCK.lock();
        for (selected, enabled) in [(0, 0xffu8), (0x1234, 0)] {
            let mut words = [0xa5a5_a5a5u32; 0x16b];
            unsafe {
                words.as_mut_ptr().cast::<u8>().add(0x5a8).write(enabled);
                SELECTED_RESOURCE_RESOLVE = missing_resolve;
                SELECTED_RESOURCE_DISPATCH = missing_dispatch;
                let mut expected = words;
                expected[0xdc / 4] = selected;
                assert_eq!(selected_resource_prepare(words.as_mut_ptr(), selected), 0x41a7);
                assert_eq!(words, expected);
            }
        }
    }

    #[test]
    fn post_draw_result_controls_string_dispatch_and_status() {
        let _guard = LOCK.lock();
        for (resolved, after_draw) in [(0, 0), (0, 7), (9, 0), (9, u32::MAX)] {
            let mut words = [0u32; 0x16b];
            unsafe {
                words.as_mut_ptr().cast::<u8>().add(0x5a8).write(0x80);
                RESULT = resolved;
                REPLACEMENT = after_draw;
                STEP = 0;
                SELECTED_RESOURCE_RESOLVE = fixture_resolve;
                SELECTED_RESOURCE_DISPATCH = fixture_dispatch;
                assert_eq!(selected_resource_prepare(words.as_mut_ptr(), 0x1234),
                    if after_draw == 0 { 0x41a7 } else { 0x41a6 });
                assert_eq!(words[0x544 / 4], after_draw);
                assert_eq!(STEP, if after_draw == 0 { 2 } else { 3 });
                SELECTED_RESOURCE_RESOLVE = missing_resolve;
                SELECTED_RESOURCE_DISPATCH = missing_dispatch;
            }
        }
    }
}
