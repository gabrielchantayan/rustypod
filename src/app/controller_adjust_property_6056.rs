//! `controller_adjust_property_6056` — `FUN_081ecf98` @ `0x081ecf98`.
//! Raw extent: 168 instruction bytes through `0x081ed03c`, followed by
//! 20 literal bytes; next real function: `0x081ed054` (188 bytes total).
//! Binary-scanned callers: 2 plain BLs, 0 predicated BLs. Body: 3 plain BLs,
//! 0 predicated BLs, one BLX and one terminal virtual BX.
//!
//! Read class-0x6000 property 0x6056 from controller word 0xde. Apply a
//! signed adjustment with stock's directional 0/100 bounds. If changed,
//! post the original adjustment, store the result in word 0x0d, update the
//! property, then dispatch slot +0x58 with ("Cntl", 0x890d) and
//! ("****", 0x8918). The property's semantic identity remains unrecovered.
//!
//! Deliberate deviations: host callbacks replace firmware calls; the final
//! virtual tail branch is expressed as a call. The existing typed-read seam
//! returns a pointer, but stock uses the raw r0 bits as a signed integer:
//! this caller casts those bits without dereferencing. Wrapping negation and
//! addition preserve ARM behavior even for i32::MIN and invalid initial values.

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct PropertyAdjustmentOps {
    pub read: unsafe extern "C" fn(u32) -> i32,
    pub post: unsafe extern "C" fn(i32),
    pub update: unsafe extern "C" fn(u32, i32),
    pub dispatch: unsafe extern "C" fn(*mut u32, u32, u32),
}
#[cfg(not(target_os = "none"))]
pub static mut PROPERTY_ADJUSTMENT_OPS: Option<PropertyAdjustmentOps> = None;

#[cfg(target_os = "none")]
unsafe fn dispatch(controller: *mut u32, kind: u32, event: u32) {
    let vtable = controller.read_volatile() as usize as *const u32;
    let notify: unsafe extern "C" fn(*mut u32, u32, u32) =
        core::mem::transmute(vtable.add(0x58 / 4).read_volatile() as usize);
    notify(controller, kind, event);
}

/// # Safety
/// `controller` must be aligned and writable through word 0xde, with a live
/// class-0x6000 store and notification vtable on target. Host callbacks must
/// be installed and must not race with this call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_adjust_property_6056(controller: *mut u32, adjustment: i32) {
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(PROPERTY_ADJUSTMENT_OPS).read().expect("property adjustment callbacks");
    let store = controller.add(0xde).read_volatile();
    #[cfg(target_os = "none")]
    let old = crate::app::class_6000_property::class6000_read_ui32_property_6056(
        store as usize as *mut crate::app::class_8900::Class6000) as usize as i32;
    #[cfg(not(target_os = "none"))]
    let old = (ops.read)(store);
    let new = if adjustment > 0 && 100i32.wrapping_sub(adjustment) <= old {
        100
    } else if adjustment < 0 && old < adjustment.wrapping_neg() {
        0
    } else { old.wrapping_add(adjustment) };
    if new == old { return; }
    #[cfg(target_os = "none")]
    crate::app::global_adjustment_notification_post::global_adjustment_notification_post(
        (0x089c_a674usize as *const *mut u8).read_volatile(), adjustment);
    #[cfg(not(target_os = "none"))]
    (ops.post)(adjustment);
    controller.add(0x0d).write_volatile(new as u32);
    // Stock reloads the store after the posting callback.
    let store = controller.add(0xde).read_volatile();
    #[cfg(target_os = "none")]
    {
        let update: unsafe extern "C" fn(*mut u8, i32) = core::mem::transmute(0x0817_2004usize);
        update(store as usize as *mut u8, new);
        dispatch(controller, 0x436e_746c, 0x890d);
        dispatch(controller, 0x2a2a_2a2a, 0x8918);
    }
    #[cfg(not(target_os = "none"))]
    {
        (ops.update)(store, new);
        (ops.dispatch)(controller, 0x436e_746c, 0x890d);
        (ops.dispatch)(controller, 0x2a2a_2a2a, 0x8918);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static STATE: Mutex<(i32, std::vec::Vec<(u32, i32)>)> = Mutex::new((0, std::vec::Vec::new()));
    unsafe extern "C" fn read(_: u32) -> i32 { STATE.lock().0 }
    unsafe extern "C" fn post(value: i32) { STATE.lock().1.push((1, value)); }
    unsafe extern "C" fn update(_: u32, value: i32) { STATE.lock().1.push((2, value)); }
    unsafe extern "C" fn notify(controller: *mut u32, kind: u32, event: u32) {
        let value = controller.add(0x0d).read() as i32;
        STATE.lock().1.push((event, value));
        assert_eq!(kind, if event == 0x890d { 0x436e_746c } else { 0x2a2a_2a2a });
    }
    #[test]
    fn directional_bounds_no_change_and_wrapping_extremes() {
        let cases = [
            (50, 0, 50), (0, -1, 0), (100, 1, 100),
            (50, 49, 99), (50, 50, 100), (50, 256, 100),
            (50, -49, 1), (50, -50, 0), (50, -51, 0),
            (0, i32::MAX, 100), (50, i32::MIN, i32::MIN + 50),
            (i32::MIN, -1, 0), (-10, 5, -5), (110, -1, 109),
        ];
        unsafe { PROPERTY_ADJUSTMENT_OPS = Some(PropertyAdjustmentOps { read, post, update, dispatch: notify }); }
        for (old, delta, expected) in cases {
            *STATE.lock() = (old, std::vec::Vec::new());
            let mut controller = [0u32; 0xdf];
            controller[0x0d] = 0xdead_beef;
            unsafe { controller_adjust_property_6056(controller.as_mut_ptr(), delta); }
            let state = STATE.lock();
            if old == expected {
                assert_eq!(controller[0x0d], 0xdead_beef);
                assert_eq!(state.1, []);
            } else {
                assert_eq!(controller[0x0d] as i32, expected, "old={old}, delta={delta}");
                assert_eq!(state.1, [(1, delta), (2, expected), (0x890d, expected), (0x8918, expected)]);
            }
        }
        unsafe { PROPERTY_ADJUSTMENT_OPS = None; }
    }
}
