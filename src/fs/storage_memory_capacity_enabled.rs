//! Storage memory-capacity gate — `FUN_080b6bec` @ `0x080b6bec`.
//!
//! True size: 8 bytes (`0x080b6bec..0x080b6bf4`). Raw words are
//! `e3a00001 e12fff1e`: `mov r0, #1; bx lr`. The next function begins
//! with a separately called push at `0x080b6bf4`. Whole-image aligned ARM
//! decoding verifies two inbound plain BLs (`0x080d6bc0`, `0x0815226c`),
//! zero predicated BLs, no outbound calls, and no aligned pointer references.
//! Returns the word 1 without reading arguments or touching memory.
//! Caller `0x080d6ba4` gates a memory-size-dependent storage adjustment;
//! caller `0x081521cc` stores the low byte at object+0x318 beside the
//! shared-context memory size in MiB at +0x31c. The particular memory region
//! is not identified. Deliberate deviations: none; the ABI returns u32,
//! not Rust bool, preserving both the word result and byte-store consumers.
//! LLVM intentionally folds this identical body into `always_succeeds`;
//! the exported symbol remains a 16-byte alias in `.text.always_succeeds`.
//! match.py cannot discover alias labels, so comparison of that body shows
//! the same return with LLVM's additional frame-pointer push/pop.

/// Enables the storage callers' shared-memory-capacity handling.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn storage_memory_capacity_enabled() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::storage_memory_capacity_enabled;

    #[test]
    fn word_gate_and_byte_flag_agree_at_capacity_boundaries() {
        // Model the two observed consumers, including the zero-MiB gate.
        let flag = storage_memory_capacity_enabled();
        assert_eq!(flag, 1);
        assert_eq!(flag as u8, 1);
        for (bytes, expected_enabled) in [
            (0u32, false),
            (0x000f_ffff, false),
            (0x0010_0000, true),
            (0x0010_0001, true),
            (u32::MAX, true),
        ] {
            assert_eq!((bytes >> 20 != 0) && flag != 0, expected_enabled);
        }
    }
}
