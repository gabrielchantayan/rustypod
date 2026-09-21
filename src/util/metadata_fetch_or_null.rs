//! `metadata_fetch_or_null` — original: `FUN_082cacec` @ `0x082cacec`.
//!
//! Load address: `0x082cacec`; true size: 16 bytes
//! (`0x082cacec..0x082cacefb`), followed by the distinct function at
//! `0x082cacfc`. Raw words are exactly `e3500000 1afe7734 03a00000 e12fff1e`:
//! `cmp r0,#0; bne 0x082689c8; mov r0,#0; bx lr`. The true extent contains
//! zero plain `bl` calls and zero predicated `bl` calls; Ghidra's 140-byte,
//! three-call reconstruction incorrectly absorbs the tail target's body.
//! Algorithm: return zero for a null metadata source; otherwise tail-transfer
//! all four observed arguments to the retail metadata-fetch implementation at
//! `0x082689c8`. Deliberate deviation: the target payload uses a conditional
//! literal veneer because its relocated address cannot encode the retail
//! PC-relative branch; host builds replace that fixed address with a callback.

/// Host/target seam for the retail implementation at `0x082689c8`.
pub type RetailMetadataFetch = unsafe extern "C" fn(u32, u32, u32, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_metadata_fetch(_r0: u32, _r1: u32, _r2: u32, _r3: u32) -> u32 {
    0
}

/// Host-only callback replacing the fixed retail target address.
#[cfg(not(target_arch = "arm"))]
pub static mut RETAIL_METADATA_FETCH: RetailMetadataFetch = missing_retail_metadata_fetch;

/// Returns zero for a null source, otherwise tail-calls retail metadata fetch.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn metadata_fetch_or_null(r0: u32, r1: u32, r2: u32, r3: u32) -> u32 {
    if r0 == 0 {
        0
    } else {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_METADATA_FETCH))(r0, r1, r2, r3) }
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
    .globl metadata_fetch_or_null
    .type metadata_fetch_or_null, %function
metadata_fetch_or_null:
    cmp     r0, #0
    ldrne   pc, 1f
    mov     r0, #0
    bx      lr
1:  .word   0x082689c8
    .size metadata_fetch_or_null, . - metadata_fetch_or_null
"#
);

#[cfg(test)]
mod tests {
    use super::{RetailMetadataFetch, RETAIL_METADATA_FETCH, metadata_fetch_or_null};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGS: (u32, u32, u32, u32) = (0, 0, 0, 0);

    unsafe extern "C" fn recording_target(r0: u32, r1: u32, r2: u32, r3: u32) -> u32 {
        unsafe {
            CALLS += 1;
            ARGS = (r0, r1, r2, r3);
        }
        r0 ^ r1.rotate_left(3) ^ r2.rotate_left(7) ^ r3.rotate_left(11)
    }

    struct TargetRestore(RetailMetadataFetch);

    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_METADATA_FETCH = self.0 };
        }
    }

    #[test]
    fn null_source_returns_zero_without_calling_retail() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_METADATA_FETCH;
            RETAIL_METADATA_FETCH = recording_target;
            CALLS = 0;
            TargetRestore(previous)
        };

        assert_eq!(unsafe { metadata_fetch_or_null(0, 1, 2, 3) }, 0);
        assert_eq!(unsafe { CALLS }, 0);
    }

    #[test]
    fn nonnull_source_forwards_all_register_arguments_and_return_value() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_METADATA_FETCH;
            RETAIL_METADATA_FETCH = recording_target;
            CALLS = 0;
            ARGS = (0, 0, 0, 0);
            TargetRestore(previous)
        };

        let result = unsafe { metadata_fetch_or_null(0x8000_0001, 0xffff_ffff, 0x1234_5678, 0x8765_4321) };

        assert_eq!(result, 0x8000_0001 ^ 0xffff_ffffu32.rotate_left(3) ^ 0x1234_5678u32.rotate_left(7) ^ 0x8765_4321u32.rotate_left(11));
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { ARGS }, (0x8000_0001, 0xffff_ffff, 0x1234_5678, 0x8765_4321));
    }
}
