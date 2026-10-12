//! Byte-guarded initialization of the shared retail runtime.
//!
//! Original: `FUN_0804be3c` @ `0x0804be3c`. True extent: 48 bytes,
//! `0x0804be3c..0x0804be6c`: 44 instruction bytes and the flag-address
//! literal at `0x0804be68`. The next function starts with `cmp r0,#0`.
//! Whole-image A32 decoding verifies two inbound plain BLs at `0x08061c60`
//! and `0x080725c4`, zero predicated inbound BLs, and one outbound plain
//! BL at `0x0804be54` to `0x082dc2a8` (zero predicated outbound BLs).
//!
//! Read the byte at `0x089cfcb8`; when zero, call the stock no-argument
//! routine at `0x082dc2a8`, then publish one. Return zero on both paths.
//! The callee's subsystem identity is not recovered and is not inferred
//! from its obfuscated implementation. Neither address has a names.yaml
//! seam to reuse. No lock, pre-call publication, or result check is added.
//! Deliberate host deviation: native flag storage and an explicitly installed
//! callback replace the fixed firmware addresses; missing callbacks fail loudly.

#[cfg(not(target_os = "none"))]
static mut INITIALIZED: u8 = 0;

/// Host substitute for the verified stock no-argument initialization call.
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_RUNTIME_INITIALIZE: Option<unsafe extern "C" fn()> = None;

#[inline(always)]
unsafe fn initialize_once(flag: *mut u8, initialize: impl FnOnce()) -> u32 {
    if flag.read_volatile() == 0 {
        initialize();
        flag.write_volatile(1);
    }
    0
}

/// Initialize the shared retail runtime if its byte guard is zero.
///
/// # Safety
/// Requires serialized access to the shared guard and all callee-owned state.
/// On firmware, the stock routine at `0x082dc2a8` must remain callable.
/// Host callers must install `RETAIL_RUNTIME_INITIALIZE` before the first call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_runtime_initialize_once() -> u32 {
    #[cfg(target_os = "none")]
    let flag = 0x089c_fcb8 as *mut u8;
    #[cfg(not(target_os = "none"))]
    let flag = core::ptr::addr_of_mut!(INITIALIZED);
    initialize_once(flag, || {
        #[cfg(target_os = "none")]
        {
            let initialize: unsafe extern "C" fn() = core::mem::transmute(0x082d_c2a8usize);
            initialize();
        }
        #[cfg(not(target_os = "none"))]
        {
            let initialize = core::ptr::addr_of!(RETAIL_RUNTIME_INITIALIZE).read()
                .expect("install retail runtime initialization host callback");
            initialize();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_only_after_initialization_and_overwrites_callback_flag_changes() {
        let mut bytes = [0xa5, 0, 0x5a];
        let flag = unsafe { bytes.as_mut_ptr().add(1) };
        let mut initialized_resource = 0;
        assert_eq!(unsafe { initialize_once(flag, || {
            assert_eq!(flag.read_volatile(), 0);
            initialized_resource = 73;
            flag.write_volatile(0xff);
        }) }, 0);
        assert_eq!(bytes, [0xa5, 1, 0x5a]);
        assert_eq!(initialized_resource, 73);
        assert_eq!(unsafe { initialize_once(flag, || panic!("initialized twice")) }, 0);
        assert_eq!(bytes, [0xa5, 1, 0x5a]);
        assert_eq!(initialized_resource, 73);
    }

    #[test]
    fn every_nonzero_guard_is_preserved_and_skips_initialization() {
        for value in 1..=255u8 {
            let mut flag = value;
            assert_eq!(unsafe { initialize_once(&mut flag, || panic!("nonzero guard")) }, 0);
            assert_eq!(flag, value);
        }
    }
}
