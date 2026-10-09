//! Active-owner AppMotor shutdown, FUN_0810073c @ 0x0810073c.
//! True extent 104 bytes, through the next push at 0x081007a4. Raw ARM
//! decoding verifies one inbound plain BL (0x08101450), one BLNE
//! (0x0812563c), and eight outbound plain BLs, no predicated outbound BLs.
//! If owner+0x100 is nonzero, request mode 1, conditionally drain owner work
//! and wait for state 3, request idle, wait until idle, finalize the owner,
//! then clear its active byte. Callee return values other than the drain
//! predicate are ignored. Unported calls retain verified retail addresses;
//! names describe their observed role, not an invented class identity.
//! Deviations: host ops replace firmware calls; existing getter and idle-wait
//! ports retain their documented deviations. No device execution claimed.

use super::wait_until_idle::{wait_until_idle, IdleWaitOwner};

type OwnerCall = unsafe extern "C" fn(*mut u8);
type MotorCall = unsafe extern "C" fn(*mut u8) -> u32;

#[derive(Clone, Copy)]
pub struct AppMotorShutdownOps {
    pub get_motor: unsafe extern "C" fn() -> *mut u8,
    pub request_mode: unsafe extern "C" fn(*mut u8, u32) -> u32,
    pub request_drain: MotorCall,
    pub drain_owner: OwnerCall,
    pub wait_state_three: OwnerCall,
    pub request_idle: MotorCall,
    pub finalize_owner: OwnerCall,
}

#[cfg(not(target_os = "none"))]
pub static mut APP_MOTOR_SHUTDOWN_OPS: Option<AppMotorShutdownOps> = None;

#[cfg(target_os = "none")]
unsafe extern "C" fn get_motor() -> *mut u8 {
    super::app_motor::app_motor_get().cast()
}

#[inline(always)]
unsafe fn shutdown(owner: *mut u8, ops: AppMotorShutdownOps) {
    let motor = (ops.get_motor)();
    (ops.request_mode)(motor, 1);
    if (ops.request_drain)(motor) != 0 {
        (ops.drain_owner)(owner);
        (ops.wait_state_three)(motor);
    }
    (ops.request_idle)(motor);
    wait_until_idle(motor.cast::<IdleWaitOwner>());
    (ops.finalize_owner)(owner);
    owner.add(0x100).write_volatile(0);
}

/// # Safety
/// Owner must have a writable active byte at +0x100 and satisfy the retail
/// drain/finalizer contracts. Motor synchronization must be initialized.
/// Host callers must install ops and serialize access to that global seam.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_motor_shutdown(owner: *mut u8) {
    if owner.add(0x100).read_volatile() == 0 { return; }
    #[cfg(target_os = "none")]
    let ops = AppMotorShutdownOps {
        get_motor,
        request_mode: core::mem::transmute(0x08295cbcusize),
        request_drain: core::mem::transmute(0x08296ad4usize),
        drain_owner: core::mem::transmute(0x08100bb4usize),
        wait_state_three: core::mem::transmute(0x08296010usize),
        request_idle: core::mem::transmute(0x08296834usize),
        finalize_owner: core::mem::transmute(0x08101738usize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = APP_MOTOR_SHUTDOWN_OPS.expect("install AppMotor shutdown firmware ops");
    shutdown(owner, ops);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut MOTOR: *mut u8 = core::ptr::null_mut();
    static mut DRAIN: u32 = 0;
    static mut FINALIZED: usize = 0;
    unsafe extern "C" fn get() -> *mut u8 { MOTOR }
    unsafe extern "C" fn mode(motor: *mut u8, mode: u32) -> u32 {
        assert_eq!(motor, MOTOR); assert_eq!(mode, 1); 0
    }
    unsafe extern "C" fn drain(motor: *mut u8) -> u32 {
        assert_eq!(motor, MOTOR); DRAIN
    }
    unsafe extern "C" fn drain_owner(owner: *mut u8) {
        assert_ne!(owner.add(0x100).read(), 0);
        owner.add(0xff).write(0x35);
    }
    unsafe extern "C" fn wait_three(motor: *mut u8) { assert_eq!(motor, MOTOR); }
    unsafe extern "C" fn idle(motor: *mut u8) -> u32 { assert_eq!(motor, MOTOR); 0 }
    unsafe extern "C" fn finish(owner: *mut u8) {
        assert_ne!(owner.add(0x100).read(), 0);
        assert_eq!(owner.add(0xff).read(), if DRAIN != 0 { 0x35 } else { 0xa5 });
        FINALIZED += 1;
    }

    #[test]
    fn inactive_skips_ops_and_active_clears_only_after_finalization() {
        let _lock = match LOCK.lock() { Ok(guard) => guard, Err(error) => error.into_inner() };
        unsafe {
            APP_MOTOR_SHUTDOWN_OPS = None;
            let mut owner = [0xa5u8; 0x104];
            owner[0x100] = 0;
            app_motor_shutdown(owner.as_mut_ptr());
            assert_eq!(owner[0xff], 0xa5);
            // Null mutex handle and initially idle predicate are valid real
            // idle-wait inputs; no host byte-offset assumptions for pointers.
            let mut motor: IdleWaitOwner = core::mem::zeroed();
            MOTOR = (&mut motor as *mut IdleWaitOwner).cast();
            APP_MOTOR_SHUTDOWN_OPS = Some(AppMotorShutdownOps {
                get_motor: get, request_mode: mode, request_drain: drain,
                drain_owner, wait_state_three: wait_three,
                request_idle: idle, finalize_owner: finish,
            });
            FINALIZED = 0;
            for predicate in [0, 1, 0x80000000, u32::MAX] {
                DRAIN = predicate;
                for active in [1, 0x80, 0xff] {
                    owner.fill(0xa5); owner[0x100] = active;
                    app_motor_shutdown(owner.as_mut_ptr());
                    assert_eq!(owner[0x100], 0);
                    assert_eq!(&owner[0x101..], &[0xa5; 3]);
                    assert!(owner[..0xff].iter().all(|&b| b == 0xa5));
                    let completed = FINALIZED;
                    app_motor_shutdown(owner.as_mut_ptr());
                    assert_eq!(FINALIZED, completed);
                }
            }
            assert_eq!(FINALIZED, 12);
            APP_MOTOR_SHUTDOWN_OPS = None;
            MOTOR = core::ptr::null_mut();
        }
    }
}
