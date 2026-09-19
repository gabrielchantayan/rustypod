//! `tail_call_retail_080cc22c` — original `thunk_FUN_080cc22c` @ 0x080035d0.
//!
//! Raw `osos.dec` words establish the true eight-byte extent
//! `0x080035d0..0x080035d7`: `ldr pc, [pc, #-4]` (`0xe51ff004`) followed by
//! literal target `0x080cc22c`; the next veneer begins at `0x080035d8`.
//! Ghidra's reported four-byte indirect call omits the literal word.
//!
//! Decoding inbound ARM BL words finds four plain `bl` callers
//! (0x08002fb0, 0x08003054, 0x080046a8, and 0x08005e34) and no predicated BL
//! callers. Each establishes only r0 before the call; the target's recovered
//! body reads its sole r0 object argument and returns its u32 result.
//!
//! # Algorithm
//!
//! Tail-transfer the observed r0 ABI to opaque retail target `0x080cc22c` and
//! return its r0 result.
//!
//! # Deliberate deviations
//!
//! The target has no established semantic identity and remains unported. ARM
//! builds retain the literal veneer exactly; host builds use an installable
//! volatile seam. The host ABI exposes only r0, the sole argument recovered
//! from both callers and target.

/// Fixed `ldr pc, [pc, #-4]` instruction at 0x080035d0.
pub const TAIL_CALL_RETAIL_080CC22C_INSN: u32 = 0xe51f_f004;

/// Literal target word at 0x080035d4.
pub const TAIL_CALL_RETAIL_080CC22C_TARGET: usize = 0x080c_c22c;

/// ABI recovered for the opaque retail tail-dispatch target.
pub type Retail080cc22c = unsafe extern "C" fn(object: *mut u8) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_080cc22c(_object: *mut u8) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_080CC22C: Retail080cc22c = missing_retail_080cc22c;

/// Tail-calls the unported retail function at 0x080cc22c.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_call_retail_080cc22c(object: *mut u8) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_080CC22C))(object) }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0, r1-r3, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_call_retail_080cc22c
    .type tail_call_retail_080cc22c, %function
tail_call_retail_080cc22c:
    ldr     pc, 1f
1:  .word   0x080cc22c
    .size tail_call_retail_080cc22c, . - tail_call_retail_080cc22c
"#
);

#[cfg(test)]
mod tests {
    use super::{
        Retail080cc22c, RETAIL_080CC22C, TAIL_CALL_RETAIL_080CC22C_INSN,
        TAIL_CALL_RETAIL_080CC22C_TARGET, tail_call_retail_080cc22c,
    };
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut OBSERVED_OBJECT: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_target(object: *mut u8) -> u32 {
        unsafe {
            CALLS += 1;
            OBSERVED_OBJECT = object;
        }
        if object.is_null() { 0x9abc_def0 } else { 0x1234_5678 }
    }

    struct TargetRestore(Retail080cc22c);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_080CC22C = self.0 };
        }
    }

    #[test]
    fn forwards_non_null_object_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_080CC22C;
            RETAIL_080CC22C = recording_target;
            CALLS = 0;
            OBSERVED_OBJECT = core::ptr::null_mut();
            TargetRestore(previous)
        };
        let mut object = [0u8; 4];
        let result = unsafe { tail_call_retail_080cc22c(object.as_mut_ptr()) };
        assert_eq!(result, 0x1234_5678);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { OBSERVED_OBJECT }, object.as_mut_ptr());
    }

    #[test]
    fn forwards_null_without_a_veneer_guard() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_080CC22C;
            RETAIL_080CC22C = recording_target;
            CALLS = 0;
            TargetRestore(previous)
        };
        let result = unsafe { tail_call_retail_080cc22c(core::ptr::null_mut()) };
        assert_eq!(result, 0x9abc_def0);
        assert_eq!(unsafe { CALLS }, 1);
        assert!(unsafe { OBSERVED_OBJECT }.is_null());
    }

    #[test]
    fn records_the_verified_veneer_words_and_distinct_entry() {
        assert_eq!(TAIL_CALL_RETAIL_080CC22C_INSN, 0xe51f_f004);
        assert_eq!(TAIL_CALL_RETAIL_080CC22C_TARGET, 0x080c_c22c);
        assert_ne!(tail_call_retail_080cc22c as *const (), recording_target as *const ());
    }
}
