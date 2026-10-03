//! Buffered read context constructor — retailOS `FUN_08267780` at load address
//! `0x08267780` (32 bytes, `0x08267780..0x082677a0`). Raw words end in
//! `bx lr`; the independently called destructor starts at `0x082677a0`.
//! Whole-image aligned A32 decoding finds two incoming plain BL calls
//! (`0x08267ac4`, `0x08267d14`), zero predicated callers, and no outgoing calls.
//!
//! Stores the source word, low byte of the open mode, and maximum read length;
//! clears allocation, length, and state in stock store order. Padding stays
//! untouched, and r0 returns the context (Ghidra's void signature omits this).
//! Deliberate deviations: target pointer words stay u32 on hosts, and volatile
//! accesses preserve the original store widths and ordering. No callee seams.

/// Initializes a buffered-read context without allocating or releasing memory.
///
/// # Safety
/// `context` must be four-byte aligned and writable through byte `0x14`.
/// Reinitializing an owning context loses its allocation, as in the firmware.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_read_context_construct(
    context: *mut u8,
    source: u32,
    open_mode: u32,
    maximum_length: u32,
) -> *mut u8 {
    let words = context.cast::<u32>();
    words.write_volatile(source);
    context.add(4).write_volatile(open_mode as u8);
    words.add(3).write_volatile(0);
    words.add(2).write_volatile(maximum_length);
    words.add(4).write_volatile(0);
    context.add(20).write_volatile(0);
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_full_width_inputs_and_preserves_padding_and_neighbors() {
        for source in [0, 1, 0x8000_0000, u32::MAX] {
            for maximum_length in [0, 1, 0x20000, u32::MAX] {
                for mode_byte in 0..=255u32 {
                    let mut storage = [0xa5a5_a5a5u32; 8];
                    let mut expected = [0xa5u8; 32];
                    expected[4..8].copy_from_slice(&source.to_le_bytes());
                    expected[8] = mode_byte as u8;
                    expected[12..16].copy_from_slice(&maximum_length.to_le_bytes());
                    expected[16..24].fill(0);
                    expected[24] = 0;
                    unsafe {
                        let context = storage.as_mut_ptr().add(1).cast::<u8>();
                        let returned = buffered_read_context_construct(
                            context, source, 0xffff_ff00 | mode_byte, maximum_length,
                        );
                        assert_eq!(returned, context);
                        let actual = core::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), 32);
                        assert_eq!(actual, expected);
                    }
                }
            }
        }
    }

    #[test]
    fn reinitialization_clears_stale_results_and_replaces_inputs() {
        let mut context = [u32::MAX; 6];
        unsafe {
            buffered_read_context_construct(context.as_mut_ptr().cast(), 0x1234, 0x80, 4096);
            context[3] = 0xdead_beef;
            context[4] = 99;
            context[5] = 0xffff_ff01;
            buffered_read_context_construct(context.as_mut_ptr().cast(), 0, 0, 0);
        }
        assert_eq!(context, [0, 0xffff_ff00, 0, 0, 0, 0xffff_ff00]);
    }
}
