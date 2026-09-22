//! Tail-call veneer for the bounded three-byte UTF-8 validator.
//!
//! `tail_call_retail_utf8_validate_three_byte` — original:
//! `thunk_FUN_08276050` @ **0x08275fec** (4 bytes,
//! `0x08275fec..0x08275ff0`; the next real function begins at `0x08275ff0`).
//! Raw osos.dec contains the single A32 word `0xea000017`, an unconditional
//! branch to `0x08276050`. A whole-disassembly scan finds **three** direct
//! inbound calls, all plain unconditional `bl` instructions; there are no
//! predicated direct `bl` calls.
//!
//! Algorithm: tail-transfer the observed r0/r1/r2 ABI and return r0 from the
//! retail target. Callers and the target body establish that it validates a
//! bounded byte sequence using the retail three-byte UTF-8 rules. Deliberate
//! deviation: the relocated ARM payload uses an absolute literal veneer rather
//! than the original PC-relative branch; its assembly preserves r0-r3, while
//! the Rust host seam models only the observed r0/r1/r2 ABI.

/// Host/target seam for the retail target at `0x08276050`.
pub type RetailUtf8ValidateThreeByte = unsafe extern "C" fn(*const u8, i32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_utf8_validate_three_byte(
    _bytes: *const u8,
    _len: i32,
    _initial_byte: u32,
) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_UTF8_VALIDATE_THREE_BYTE: RetailUtf8ValidateThreeByte =
    missing_retail_utf8_validate_three_byte;

/// Tail-calls the unported retail validator at `0x08276050`.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn tail_call_retail_utf8_validate_three_byte(
    bytes: *const u8,
    len: i32,
    initial_byte: u32,
) -> u32 {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_UTF8_VALIDATE_THREE_BYTE))(
            bytes,
            len,
            initial_byte,
        )
    }
}

// A literal veneer remains reachable after this code moves into the patch
// payload and preserves r0-r3, lr, and the retail target's return value.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl tail_call_retail_utf8_validate_three_byte
    .type tail_call_retail_utf8_validate_three_byte, %function
tail_call_retail_utf8_validate_three_byte:
    ldr     pc, 1f
1:  .word   0x08276050
    .size tail_call_retail_utf8_validate_three_byte, . - tail_call_retail_utf8_validate_three_byte
"#
);

#[cfg(test)]
mod tests {
    use super::{
        RetailUtf8ValidateThreeByte, RETAIL_UTF8_VALIDATE_THREE_BYTE,
        tail_call_retail_utf8_validate_three_byte,
    };
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (*const u8, i32, u32) = (core::ptr::null(), 0, 0);

    unsafe extern "C" fn recording_target(bytes: *const u8, len: i32, initial_byte: u32) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = (bytes, len, initial_byte);
        }
        0x8000_0000 | initial_byte ^ len as u32
    }

    struct TargetRestore(RetailUtf8ValidateThreeByte);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_UTF8_VALIDATE_THREE_BYTE = self.0 };
        }
    }

    #[test]
    fn forwards_all_observed_arguments_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let text = [0xf0, 0x9f, 0x92, 0xa9];
        let _restore = unsafe {
            let previous = RETAIL_UTF8_VALIDATE_THREE_BYTE;
            RETAIL_UTF8_VALIDATE_THREE_BYTE = recording_target;
            CALLS = 0;
            ARGS = (core::ptr::null(), 0, 0);
            TargetRestore(previous)
        };

        let result = unsafe {
            tail_call_retail_utf8_validate_three_byte(text.as_ptr(), -7, 0x1234_5678)
        };

        assert_eq!(result, 0xedcb_a981);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { ARGS }, (text.as_ptr(), -7, 0x1234_5678));
    }
}
