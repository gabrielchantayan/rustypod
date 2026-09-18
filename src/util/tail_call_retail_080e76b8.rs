//! `tail_call_retail_080e76b8` — original: `thunk_FUN_080e76b8` @
//! `0x080f0fb0` (4 bytes; true extent `0x080f0fb0..0x080f0fb4`, followed by
//! the distinct `element_array1_at` function).
//!
//! Raw ARM is exactly `b 0x080e76b8`. Decoding every ARM B/BL word in
//! `osos.dec` finds four direct inbound calls, all plain unconditional `bl`:
//! `0x0824c0a8`, `0x0824c1bc`, `0x0824c258`, and `0x0824c370`; there are no
//! predicated direct `bl` calls. Algorithm: tail-transfer r0/r1 to the retail
//! target and return its r0 result. Deliberate deviation: the ARM payload uses
//! an absolute literal veneer because its relocated address cannot encode the
//! retail PC-relative branch; it preserves the tail-call register contract.

/// Host/target seam for the retail target at `0x080e76b8`.
pub type Retail080e76b8 = unsafe extern "C" fn(u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_080e76b8(_r0: u32, _r1: u32) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_080E76B8: Retail080e76b8 = missing_retail_080e76b8;

/// Tail-calls the unported retail function at `0x080e76b8`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_call_retail_080e76b8(r0: u32, r1: u32) -> u32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_080E76B8))(r0, r1) }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0, r1, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_call_retail_080e76b8
    .type tail_call_retail_080e76b8, %function
tail_call_retail_080e76b8:
    ldr     pc, 1f
1:  .word   0x080e76b8
    .size tail_call_retail_080e76b8, . - tail_call_retail_080e76b8
"#
);

#[cfg(test)]
mod tests {
    use super::{Retail080e76b8, RETAIL_080E76B8, tail_call_retail_080e76b8};
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

    struct TargetRestore(Retail080e76b8);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_080E76B8 = self.0 };
        }
    }

    #[test]
    fn forwards_all_register_arguments_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_080E76B8;
            RETAIL_080E76B8 = recording_target;
            CALLS = 0;
            ARGS = (0, 0);
            TargetRestore(previous)
        };

        let result = unsafe { tail_call_retail_080e76b8(0x8000_0001, 0xffff_ffff) };

        assert_eq!(result, 0xffff_ff3f);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { ARGS }, (0x8000_0001, 0xffff_ffff));
    }
}
