//! Remove a clock selection — `FUN_08284b40` @ 0x08284b40.
//! True extent: 76 bytes (68 instruction bytes and 8 literal bytes), ending
//! at the independent entry 0x08284b8c. Raw A32 decoding verifies two inbound
//! plain BLs (0x08274c98, 0x08274da4), no predicated BLs; the body has two
//! plain BLs and no predicated BLs, then a virtual tail BX through +0x58.
//!
//! Reject negative indices without reading the object; otherwise reject when
//! the signed count at +0x2c is <= index. Erase from the embedded array at
//! +0x28 via verified retail entry 0x083cff30, mark pending and dispatch via
//! the existing port, then reload the vtable and notify with 'VMax', 0x6182.
//! Deliberate deviations: unported erase remains a retail-address seam;
//! host callbacks model its effects and pending dispatch. Hosts store a native
//! vtable pointer in the first pointer-width bytes, and native function slots;
//! all remaining object fields retain target word indices. No return value
//! is specified by callers; the virtual callback's result is discarded.

pub type ClockErase = unsafe extern "C" fn(*mut u32, i32) -> i32;
pub type ClockPending = unsafe extern "C" fn(*mut u32);
pub type ClockNotify = unsafe extern "C" fn(*mut u32, u32, u32);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_erase(_: *mut u32, _: i32) -> i32 {
    panic!("clock erase requires retail entry 0x083cff30")
}
#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_pending(_: *mut u32) {
    panic!("clock pending dispatch requires a host model")
}
#[cfg(not(target_arch = "arm"))]
pub static mut CLOCK_ERASE: ClockErase = missing_erase;
#[cfg(not(target_arch = "arm"))]
pub static mut CLOCK_PENDING: ClockPending = missing_pending;

#[cfg(target_arch = "arm")]
extern "C" {
    fn controller_mark_pending_and_dispatch(controller: *mut u8, mode: u32) -> u32;
}

/// # Safety
/// For nonnegative indices, `clock` must be aligned and readable through word
/// 11. Accepted indices require the complete controller and embedded array,
/// valid erase/dispatcher contracts, and a callable vtable slot at +0x58.
/// Host fixtures use a native pointer at the object start and native slots.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn clock_remove_selection(clock: *mut u32, index: i32) {
    if index < 0 || clock.add(11).read() as i32 <= index {
        return;
    }
    #[cfg(target_arch = "arm")]
    {
        let erase: ClockErase = core::mem::transmute(0x083c_ff30usize);
        erase(clock.add(10), index);
        controller_mark_pending_and_dispatch(clock.cast(), 1);
    }
    #[cfg(not(target_arch = "arm"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(CLOCK_ERASE))(clock.add(10), index);
        core::ptr::read_volatile(core::ptr::addr_of!(CLOCK_PENDING))(clock);
    }
    #[cfg(target_arch = "arm")]
    let notify: ClockNotify = {
        let vtable = clock.read() as *const u32;
        core::mem::transmute(vtable.add(0x58 / 4).read())
    };
    #[cfg(not(target_arch = "arm"))]
    let notify: ClockNotify = {
        let vtable = clock.cast::<*const ClockNotify>().read();
        vtable.add(0x58 / 4).read()
    };
    notify(clock, 0x564d_6178, 0x6182);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    #[repr(C, align(8))]
    struct Fixture([u32; 32]);
    static mut PHASE: u32 = 0;
    static mut REPLACEMENT: *const ClockNotify = core::ptr::null();

    unsafe extern "C" fn erase(array: *mut u32, index: i32) -> i32 {
        assert_eq!(PHASE, 0);
        assert!(index >= 0 && index < array.add(1).read() as i32);
        array.add(1).write(array.add(1).read() - 1);
        PHASE = 1;
        -1 // The erase result must not suppress pending dispatch or notification.
    }
    unsafe extern "C" fn pending(clock: *mut u32) {
        assert_eq!(PHASE, 1);
        clock.cast::<*const ClockNotify>().write(REPLACEMENT);
        clock.cast::<u8>().add(0x5c).write(1);
        PHASE = 2;
    }
    unsafe extern "C" fn stale(_: *mut u32, _: u32, _: u32) {
        panic!("notification used the pre-dispatch vtable")
    }
    unsafe extern "C" fn notify(clock: *mut u32, event: u32, code: u32) {
        assert_eq!(PHASE, 2);
        assert_eq!((event, code), (0x564d6178, 0x6182));
        assert_eq!(clock.cast::<u8>().add(0x5c).read(), 1);
        PHASE = 3;
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { unsafe {
            CLOCK_ERASE = missing_erase;
            CLOCK_PENDING = missing_pending;
            REPLACEMENT = core::ptr::null();
        } }
    }
    #[test]
    fn signed_bounds_and_ordered_removal_reload_the_vtable() {
        let _lock = LOCK.lock();
        let _reset = Reset;
        let old = [stale as ClockNotify; 23];
        let new = [notify as ClockNotify; 23];
        unsafe {
            CLOCK_ERASE = erase;
            CLOCK_PENDING = pending;
            REPLACEMENT = new.as_ptr();
            for count in [i32::MIN, -1, 0, 1, 3, i32::MAX] {
                for index in [i32::MIN, -1, 0, 1, 2, 3, i32::MAX] {
                    let mut fixture = Fixture([0xa5a5a5a5; 32]);
                    let clock = fixture.0.as_mut_ptr();
                    clock.cast::<*const ClockNotify>().write(old.as_ptr());
                    clock.add(11).write(count as u32);
                    let before = fixture.0;
                    PHASE = 0;
                    clock_remove_selection(clock, index);
                    if index >= 0 && index < count {
                        assert_eq!(PHASE, 3);
                        assert_eq!(clock.add(11).read() as i32, count - 1);
                    } else {
                        assert_eq!(PHASE, 0);
                        assert_eq!(fixture.0, before);
                    }
                }
            }
            clock_remove_selection(core::ptr::null_mut(), -1);
            clock_remove_selection(core::ptr::null_mut(), i32::MIN);
        }
    }
}
