//! Set the app-screen context and mode — `FUN_08174484` @ `0x08174484`.
//! True extent: 140 bytes, ending at the next entry `0x08174510`.
//! Raw A32 decoding finds two inbound plain BLs (0x081e0f80, 0x08260914),
//! zero predicated inbound BLs; four outbound plain BLs, zero predicated BLs,
//! one virtual BLX, and a tail B to 0x081779c8.
//!
//! Replace the handle at +0x18 unless the source is that same slot. For mode
//! one, query implementation vtable slot +0xac with mutable copies of the
//! incoming detail and mode; detail 16 promotes mode to two. Store the low
//! bytes of the selected mode, ORIGINAL detail, and flags at +0x24..+0x26,
//! then update the mode-dependent screen and tail-dispatch its notifications.
//! Query changes to the copied mode do not affect the selected mode.
//!
//! Deviations: native-pointer handle/vtable access supports host fixtures;
//! target offsets remain exact. The unported mode-dependent helper and
//! notification helper retain their verified entry addresses, not invented
//! callee identities. Ghidra incorrectly includes the tail helper's body.

use crate::cxx::handle::{RefcountedBody, handle_deref_or_null,
    refcounted_body_acquire, refcounted_body_release};

type ModeUpdate = unsafe extern "C" fn(*mut u8, u32);
type Notify = unsafe extern "C" fn(*mut u8);
type Query = unsafe extern "C" fn(*mut u8, *mut u32, *mut u32);

#[inline(always)]
unsafe fn update(screen: *mut u8, mode: u32) {
    #[cfg(target_os = "none")]
    {
        let call: ModeUpdate = core::mem::transmute(0x08174368usize);
        call(screen, mode);
    }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_MODE_UPDATE)))(screen, mode); }
}

#[inline(always)]
unsafe fn notify(screen: *mut u8) {
    #[cfg(target_os = "none")]
    {
        let call: Notify = core::mem::transmute(0x081779c8usize);
        call(screen);
    }
    #[cfg(not(target_os = "none"))]
    { (core::ptr::read_volatile(core::ptr::addr_of!(SCREEN_CONTEXT_NOTIFY)))(screen); }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_update(_: *mut u8, _: u32) { panic!("retail screen mode helper unavailable on host") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_notify(_: *mut u8) { panic!("retail screen notification helper unavailable on host") }
#[cfg(not(target_os = "none"))]
pub static mut SCREEN_MODE_UPDATE: ModeUpdate = missing_update;
#[cfg(not(target_os = "none"))]
pub static mut SCREEN_CONTEXT_NOTIFY: Notify = missing_notify;

/// # Safety
/// Screen must have a writable handle at +0x18 and bytes +0x24..+0x26.
/// Source must be a valid handle slot. Mode one requires a non-NULL
/// implementation with callable vtable slot +0xac. Both downstream retail
/// helpers require a complete live screen. No NULL validation is added.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn app_screen_set_context_mode(
    screen: *mut u8, source: *const *mut RefcountedBody,
    mode: u32, detail: u32, flags: u32,
) {
    let slot = screen.add(0x18).cast::<*mut RefcountedBody>();
    if slot.cast_const() != source {
        refcounted_body_release(slot);
        refcounted_body_acquire(slot, source.read());
    }
    let mut selected_mode = mode;
    if mode == 1 {
        let object = handle_deref_or_null(slot.cast());
        let vtable = object.cast::<*const usize>().read();
        let query: Query = core::mem::transmute(vtable.add(0xac / 4).read());
        let mut queried_detail = detail;
        let mut queried_mode = mode;
        query(object, &mut queried_detail, &mut queried_mode);
        if queried_detail == 16 { selected_mode = 2; }
    }
    screen.add(0x24).write(selected_mode as u8);
    screen.add(0x25).write(detail as u8);
    screen.add(0x26).write(flags as u8);
    update(screen, selected_mode);
    notify(screen);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[repr(C)]
    struct Object { vtable: *const usize }
    #[repr(align(8))]
    struct Screen([u8; 64]);

    unsafe extern "C" fn query(_: *mut u8, detail: *mut u32, mode: *mut u32) {
        assert_eq!(mode.read(), 1);
        // Only this exact full-width input promotes; no byte comparison.
        if detail.read() == 0x110 { detail.write(16); }
        mode.write(99);
    }
    unsafe extern "C" fn mode_update(screen: *mut u8, mode: u32) {
        assert_eq!(screen.add(0x24).read(), mode as u8);
        screen.add(0x30).cast::<u32>().write(mode);
    }
    unsafe extern "C" fn notification(screen: *mut u8) {
        // Make downstream order observable without global recorder state.
        let selected = screen.add(0x30).cast::<u32>().read();
        assert_eq!(selected as u8, screen.add(0x24).read());
        screen.add(0x34).cast::<u32>().write(selected.wrapping_add(7));
    }

    #[test]
    fn replacement_self_assignment_query_and_full_width_mode() {
        unsafe {
            SCREEN_MODE_UPDATE = mode_update;
            SCREEN_CONTEXT_NOTIFY = notification;
            let mut table = [0usize; 44];
            table[43] = query as *const () as usize;
            let mut object = Object { vtable: table.as_ptr() };
            let mut old = RefcountedBody { opaque0: 0, refcount: 3, mutex: core::ptr::null_mut() };
            let mut new = RefcountedBody { opaque0: &mut object as *mut Object as usize,
                refcount: 4, mutex: core::ptr::null_mut() };
            let source = &mut new as *mut RefcountedBody;
            let mut screen = Screen([0xa5; 64]);
            let p = screen.0.as_mut_ptr();
            let slot = p.add(0x18).cast::<*mut RefcountedBody>();
            slot.write(&mut old);
            app_screen_set_context_mode(p, &source, 1, 0x110, 0x1ff);
            assert_eq!(old.refcount, 2);
            assert_eq!(new.refcount, 5);
            assert_eq!(slot.read(), source);
            assert_eq!(&screen.0[0x24..0x28], &[2, 0x10, 0xff, 0xa5]);
            assert_eq!(p.add(0x34).cast::<u32>().read(), 9);
            app_screen_set_context_mode(p, slot, 1, 17, 0);
            assert_eq!(new.refcount, 5);
            assert_eq!(&screen.0[0x24..0x27], &[1, 17, 0]);
            assert_eq!(p.add(0x34).cast::<u32>().read(), 8);
            app_screen_set_context_mode(p, slot, 0x101, 0x210, 0x100);
            assert_eq!(&screen.0[0x24..0x27], &[1, 0x10, 0]);
            assert_eq!(p.add(0x30).cast::<u32>().read(), 0x101);
            let empty = core::ptr::null_mut();
            app_screen_set_context_mode(p, &empty, 0, 0, 0);
            assert!(slot.read().is_null());
            assert_eq!(new.refcount, 4);
            SCREEN_MODE_UPDATE = missing_update;
            SCREEN_CONTEXT_NOTIFY = missing_notify;
        }
    }
}
