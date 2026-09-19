//! `tail_call_retail_080cfe50` — original: `thunk_FUN_080cfe50` @
//! `0x080035d8` (8 bytes; true extent `0x080035d8..0x080035e0`, followed by
//! the distinct `thunk_FUN_080cc234` veneer).
//!
//! Raw ARM words are exactly `ldr pc, [pc, #-4]; .word 0x080cfe50`. Decoding
//! every ARM branch-with-link word in `osos.dec` finds four direct inbound
//! calls, all plain unconditional `bl`; there are no predicated direct `bl`
//! calls. Algorithm: tail-transfer the observed r0/r1 ABI to the retail target
//! and return its r0 result. Deliberate deviation: the ARM payload uses an
//! absolute literal veneer because its relocated address cannot encode the
//! retail PC-relative transfer; r2/r3 are not modeled by the Rust ABI, while
//! the target veneer itself preserves all register arguments.

/// Host/target seam for the retail target at `0x080cfe50`.
pub type Retail080cfe50 = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_080cfe50(_r0: u32, _r1: u32) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_080CFE50: Retail080cfe50 = missing_retail_080cfe50;

/// Tail-calls the unported retail function at `0x080cfe50`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_call_retail_080cfe50(r0: u32, r1: u32) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_080CFE50))(r0, r1) }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0, r1, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_call_retail_080cfe50
    .type tail_call_retail_080cfe50, %function
tail_call_retail_080cfe50:
    ldr     pc, 1f
1:  .word   0x080cfe50
    .size tail_call_retail_080cfe50, . - tail_call_retail_080cfe50
"#
);

#[cfg(test)]
mod tests {
    use super::{Retail080cfe50, RETAIL_080CFE50, tail_call_retail_080cfe50};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (u32, u32) = (0, 0);

    unsafe extern "C" fn recording_target(r0: u32, r1: u32) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = (r0, r1);
        }
        r0.rotate_left(7) ^ r1
    }

    struct TargetRestore(Retail080cfe50);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_080CFE50 = self.0 };
        }
    }

    #[test]
    fn forwards_observed_arguments_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_080CFE50;
            RETAIL_080CFE50 = recording_target;
            CALLS = 0;
            ARGS = (0, 0);
            TargetRestore(previous)
        };

        let result = unsafe { tail_call_retail_080cfe50(0x8000_0001, 0xffff_ffff) };

        assert_eq!(result, 0xffff_ff3f);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { ARGS }, (0x8000_0001, 0xffff_ffff));
    }
}
