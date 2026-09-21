//! Input dispatch wrapper.
//!
//! `input_dispatch` — original: `FUN_0834be0c` @ `0x0834be0c`
//! (**48 bytes**, `0x0834be0c..0x0834be3c`; the next independently linked
//! function begins at `0x0834be3c`). Raw ARM B/BL decoding finds three inbound
//! plain `bl` calls (`0x08321800`, `0x08323ff8`, and `0x083243a0`) and no
//! predicated `bl` calls. The body itself has no BL instructions; its one
//! conditional plain `b` tail-transfers to the unported `0x08317f9c`.
//!
//! # Algorithm
//!
//! Return the supplied length when the input pointer is NULL. Otherwise,
//! tail-dispatch to retail `0x08317f9c`, preserving the three observed ABI
//! words `(length, input, state)`.
//!
//! # Deliberate deviations
//!
//! The relocated ARM payload reaches the unported tail target through an
//! absolute literal veneer. Host builds replace it with a test callback.

/// ABI of the unported retail tail target at `0x08317f9c`.
pub type Retail08317f9c = unsafe extern "C" fn(u32, *mut u8, *mut u8) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_08317f9c(_length: u32, _input: *mut u8, _state: *mut u8) -> u32 {
    0
}

/// Host-only replacement for the fixed retail tail target.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_08317F9C: Retail08317f9c = missing_retail_08317f9c;

/// Dispatches non-NULL input to the retail state handler.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_dispatch(input: *mut u8, length: u32, state: *mut u8) -> u32 {
    if input.is_null() {
        length
    } else {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_08317F9C))(length, input, state) }
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl input_dispatch
    .type input_dispatch, %function
input_dispatch:
    mov     r3, r0
    mov     r0, r1
    movs    r1, r3
    movne   r3, #0
    moveq   r3, #1
    cmp     r3, #0
    bxne    lr
    ldr     pc, 1f
1:  .word   0x08317f9c
    .size input_dispatch, . - input_dispatch
"#
);

#[cfg(test)]
mod tests {
    use super::{Retail08317f9c, RETAIL_08317F9C, input_dispatch};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (u32, usize, usize) = (0, 0, 0);

    unsafe extern "C" fn recording_target(length: u32, input: *mut u8, state: *mut u8) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = (length, input as usize, state as usize);
        }
        0x5a
    }

    struct TargetRestore(Retail08317f9c);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_08317F9C = self.0 };
        }
    }

    #[test]
    fn returns_length_without_dispatch_for_null_input() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_08317F9C;
            RETAIL_08317F9C = recording_target;
            CALLS = 0;
            TargetRestore(previous)
        };
        let mut state = [0u8; 1];

        assert_eq!(unsafe { input_dispatch(core::ptr::null_mut(), 0, state.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { input_dispatch(core::ptr::null_mut(), u32::MAX, state.as_mut_ptr()) }, u32::MAX);
        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn dispatches_every_nonnull_input_with_observed_abi() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_08317F9C;
            RETAIL_08317F9C = recording_target;
            CALLS = 0;
            ARGS = (0, 0, 0);
            TargetRestore(previous)
        };
        let mut input = [0u8; 1];
        let mut state = [0u8; 1];

        assert_eq!(unsafe { input_dispatch(input.as_mut_ptr(), 0, state.as_mut_ptr()) }, 0x5a);
        assert_eq!(unsafe { input_dispatch(input.as_mut_ptr(), u32::MAX, state.as_mut_ptr()) }, 0x5a);
        assert_eq!(unsafe { CALLS }, 2);
        assert_eq!(unsafe { ARGS }, (u32::MAX, input.as_mut_ptr() as usize, state.as_mut_ptr() as usize));
    }
}
