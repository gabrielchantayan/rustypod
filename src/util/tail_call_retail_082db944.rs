//! `tail_call_retail_082db944` — original: `thunk_FUN_082db944` @
//! `0x080034b8` (8 bytes; true extent `0x080034b8..0x080034c0`, followed by
//! a distinct literal veneer).
//!
//! Raw ARM words are exactly `ldr pc, [pc, #-4]; .word 0x082db944`. Decoding
//! every ARM branch-with-link word in `osos.dec` finds three direct inbound
//! calls, all plain unconditional `bl`; there are no predicated direct `bl`
//! calls. Algorithm: tail-transfer the observed r0/r1/r2 ABI to the retail
//! target and return its r0 result. Deliberate deviation: the ARM payload uses
//! an absolute literal veneer because its relocated address cannot encode the
//! retail PC-relative transfer; the target's identity and argument meanings
//! remain unverified, so this seam preserves the three observed ABI words.

/// Host/target seam for the retail target at `0x082db944`.
pub type Retail082db944 = unsafe extern "C" fn(u32, u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_082db944(_r0: u32, _r1: u32, _r2: u32) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_082DB944: Retail082db944 = missing_retail_082db944;

/// Tail-calls the unported retail function at `0x082db944`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_call_retail_082db944(r0: u32, r1: u32, r2: u32) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_082DB944))(r0, r1, r2) }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0-r3, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_call_retail_082db944
    .type tail_call_retail_082db944, %function
tail_call_retail_082db944:
    ldr     pc, 1f
1:  .word   0x082db944
    .size tail_call_retail_082db944, . - tail_call_retail_082db944
"#
);

#[cfg(test)]
mod tests {
    use super::{Retail082db944, RETAIL_082DB944, tail_call_retail_082db944};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (u32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn recording_target(r0: u32, r1: u32, r2: u32) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = (r0, r1, r2);
        }
        r0.rotate_left(7) ^ r1.rotate_right(3) ^ r2
    }

    struct TargetRestore(Retail082db944);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_082DB944 = self.0 };
        }
    }

    #[test]
    fn forwards_all_observed_arguments_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_082DB944;
            RETAIL_082DB944 = recording_target;
            CALLS = 0;
            ARGS = (0, 0, 0);
            TargetRestore(previous)
        };

        let result = unsafe {
            tail_call_retail_082db944(0x8000_0001, 0xffff_ffff, 0x1234_5678)
        };

        assert_eq!(result, 0xedcb_a947);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { ARGS }, (0x8000_0001, 0xffff_ffff, 0x1234_5678));
    }
}
