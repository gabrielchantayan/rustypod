//! `cg_mode_limit` — original: `FUN_080cc950` @ **0x080cc950**.
//!
//! Raw `osos.dec` words establish the 36-byte body
//! `0x080cc950..0x080cc973`; the next independently linked function starts
//! at `0x080cc978`. Its body contains **1 plain, unconditional `bl` call**
//! (at `0x080cc968`) and no predicated calls. It reads the signed cached mode
//! limit at `0x089cab58`; values other than -1 are returned directly. The -1
//! sentinel calls `0x082e5648` to fill a one-byte local result, which is then
//! sign-extended for the return value.
//!
//! Deliberate deviations: Rust initializes that local byte to zero rather
//! than preserving the target's caller-supplied `r3` stack word. The verified
//! callee writes the output byte on both of its paths, so this removes only
//! undefined intermediate state. Its subsystem identity is unproven; the
//! seam is named solely for its observed cache-refresh role.

#[cfg(test)]
extern crate std;

#[cfg(not(target_arch = "arm"))]
use core::ptr;

pub type ModeLimitRefresh = unsafe extern "C" fn(*mut i8);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn mode_limit_refresh_zero(out: *mut i8) { *out = 0; }

#[cfg(not(target_arch = "arm"))]
pub static mut CG_MODE_LIMIT_CACHE: i8 = -1;
#[cfg(not(target_arch = "arm"))]
pub static mut CG_MODE_LIMIT_REFRESH: ModeLimitRefresh = mode_limit_refresh_zero;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_cg_mode_limit_refresh(out: *mut i8);
}

#[cfg(not(target_arch = "arm"))]
unsafe fn retail_cg_mode_limit_refresh(out: *mut i8) {
    ptr::read_volatile(ptr::addr_of!(CG_MODE_LIMIT_REFRESH))(out)
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_cg_mode_limit_refresh
retail_cg_mode_limit_refresh:
    ldr pc, [pc, #-4]
    .word 0x082e5648
"#);

#[inline]
unsafe fn cached_mode_limit() -> i8 {
    #[cfg(target_arch = "arm")]
    { core::ptr::read_volatile(0x089cab58 as *const i8) }
    #[cfg(not(target_arch = "arm"))]
    { ptr::read_volatile(ptr::addr_of!(CG_MODE_LIMIT_CACHE)) }
}

/// Returns the cached code-generator mode limit, refreshing its -1 sentinel.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_mode_limit() -> i32 {
    let cached = cached_mode_limit();
    if cached == -1 {
        let mut refreshed = 0i8;
        retail_cg_mode_limit_refresh(&mut refreshed);
        refreshed as i32
    } else {
        cached as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut REFRESH_VALUE: i8 = 0;
    static mut REFRESH_CALLS: u32 = 0;

    unsafe extern "C" fn refresh(out: *mut i8) {
        REFRESH_CALLS += 1;
        *out = REFRESH_VALUE;
    }

    #[test]
    fn cached_non_sentinel_values_are_signed_and_do_not_refresh() {
        let _lock = LOCK.lock();
        unsafe {
            CG_MODE_LIMIT_REFRESH = refresh;
            CG_MODE_LIMIT_CACHE = -128;
            REFRESH_CALLS = 0;
            assert_eq!(cg_mode_limit(), -128);
            CG_MODE_LIMIT_CACHE = 7;
            assert_eq!(cg_mode_limit(), 7);
            assert_eq!(REFRESH_CALLS, 0);
        }
    }

    #[test]
    fn sentinel_refreshes_one_byte_result_and_sign_extends_it() {
        let _lock = LOCK.lock();
        unsafe {
            CG_MODE_LIMIT_REFRESH = refresh;
            CG_MODE_LIMIT_CACHE = -1;
            REFRESH_VALUE = -2;
            REFRESH_CALLS = 0;
            assert_eq!(cg_mode_limit(), -2);
            assert_eq!(REFRESH_CALLS, 1);
        }
    }
}
