//! Refresh an object's RTC binding from TMediaNowPlayingCntlr.
//!
//! Original FUN_08160254 at 0x08160254: true size 64 bytes, ending at
//! 0x08160294, where the next function begins with ldrb r0,[r0,#0x52].
//! Whole-image raw A32 decoding verifies two inbound plain BLs at
//! 0x08116e0c and 0x081605e0, zero predicated inbound BLs, three outbound
//! plain BLs, zero predicated outbound BLs, and a bx r2 virtual tail call.
//! Follow singleton +0x28 -> +0x30 to the RTC owner, store its context
//! handle at destination +0x54, then invoke destination vtable +0x84 with
//! the owner's companion word. No NULL checks or zero-value shortcuts.
//!
//! Deviations: host builds inject singleton lookup and use native-width
//! pointer fields/vtable entries at the same fixed field offsets. The
//! virtual call's r0 result is preserved despite Ghidra's void signature.
//! All three production dependencies reuse existing ports.

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_controller() -> *mut u8 {
    panic!("install RTC binding controller lookup")
}

#[cfg(not(target_os = "none"))]
pub static mut RTC_BINDING_CONTROLLER: unsafe extern "C" fn() -> *mut u8 = missing_controller;

/// # Safety
/// The singleton's +0x28/+0x30 chain and RTC owner must be valid. `object`
/// must have writable +0x54 storage and a callable vtable +0x84 slot.
/// Host lookup installation must be serialized against all callers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn rtc_binding_refresh(object: *mut u8) -> u32 {
    #[cfg(target_os = "none")]
    let controller = crate::app::registry::instance_of_class_3280();
    #[cfg(not(target_os = "none"))]
    let controller = RTC_BINDING_CONTROLLER();
    let holder = controller.add(0x28).cast::<*const u8>().read();
    let owner = holder.add(0x30).cast::<*const u8>().read();
    let handle = crate::time::rtc::rtc_context_handle(owner.cast());
    object.add(0x54).cast::<u32>().write(handle);
    let companion = crate::ui::object_state::object_nested_companion_word(owner);
    let vtable = object.cast::<*const usize>().read();
    let refresh: unsafe extern "C" fn(*mut u8, u32) -> u32 =
        core::mem::transmute(vtable.add(0x84 / 4).read());
    refresh(object, companion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONTROLLER: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn lookup() -> *mut u8 { CONTROLLER }
    unsafe extern "C" fn refresh(object: *mut u8, companion: u32) -> u32 {
        let handle = object.add(0x54).cast::<u32>().read();
        let generation = object.add(0x58).cast::<u32>();
        generation.write(generation.read().wrapping_add(1));
        handle.rotate_left(7) ^ companion
    }
    unsafe extern "C" fn wrong(_: *mut u8, _: u32) -> u32 { panic!("wrong vtable slot") }
    #[repr(align(8))]
    struct Bytes<const N: usize>([u8; N]);

    #[test]
    fn replaces_binding_before_dispatch_even_for_zero_and_high_words() {
        let _lock = LOCK.lock();
        unsafe {
            let saved = RTC_BINDING_CONTROLLER;
            let mut controller = Bytes([0u8; 0x38]);
            let mut holder = Bytes([0u8; 0x40]);
            let mut owner = Bytes([0u8; 0xf08]);
            let mut context = Bytes([0u8; 0xb98]);
            let mut object = Bytes([0xa5u8; 0x60]);
            let mut vtable = [wrong as usize; 0x84 / 4 + 2];
            vtable[0x84 / 4] = refresh as usize;
            controller.0.as_mut_ptr().add(0x28).cast::<*mut u8>().write(holder.0.as_mut_ptr());
            holder.0.as_mut_ptr().add(0x30).cast::<*mut u8>().write(owner.0.as_mut_ptr());
            owner.0.as_mut_ptr().add(0xf00).cast::<*mut u8>().write(context.0.as_mut_ptr());
            object.0.as_mut_ptr().cast::<*const usize>().write(vtable.as_ptr());
            object.0.as_mut_ptr().add(0x58).cast::<u32>().write(u32::MAX);
            CONTROLLER = controller.0.as_mut_ptr();
            RTC_BINDING_CONTROLLER = lookup;
            for (index, (handle, companion)) in [(0u32, 0u32), (u32::MAX, 0x8000_0000), (0x8000_0000, u32::MAX), (1, 0)].into_iter().enumerate() {
                context.0.as_mut_ptr().add(0x0c).cast::<u32>().write(handle);
                context.0.as_mut_ptr().add(0xb54).cast::<u32>().write(companion);
                assert_eq!(rtc_binding_refresh(object.0.as_mut_ptr()), handle.rotate_left(7) ^ companion);
                assert_eq!(object.0.as_ptr().add(0x54).cast::<u32>().read(), handle);
                assert_eq!(object.0.as_ptr().add(0x58).cast::<u32>().read(), index as u32);
                assert_eq!(&object.0[0x50..0x54], &[0xa5; 4]);
                assert_eq!(&object.0[0x5c..], &[0xa5; 4]);
            }
            RTC_BINDING_CONTROLLER = saved;
            CONTROLLER = core::ptr::null_mut();
        }
    }
}
