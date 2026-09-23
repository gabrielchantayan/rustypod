//! Surface configuration copy — `FUN_081f5cdc` @ `0x081f5cdc`.
//!
//! The 120-byte A32 body is `0x081f5cdc..0x081f5d53`; the following `push`
//! at `0x081f5d54` starts a separately linked function. Raw A32 decoding
//! confirms three inbound plain `bl` sites (two at `0x081f5c7c` and
//! `0x081f5c8c`, one at `0x081f602c`) and no predicated inbound `bl` sites.
//! Copies the input pixel format and paired dimension words into an initialized
//! 64-byte surface descriptor, selects the format-specific opaque fields, and
//! clears its fixed bookkeeping words. The first ABI argument is intentionally
//! unused, matching retailOS. Rust expresses the ARM conditional stores as a
//! `match`; volatile accesses retain the observable separate reads and writes.

/// The input record passed to [`copy_surface_config`].
///
/// Its two words have established byte offsets but no established domain
/// meaning, so their names preserve the observed layout.
#[repr(C)]
pub struct LayerConfigInput {
    pub(crate) reserved_0_7: [u8; 8],
    pub(crate) pixel_format: u8,
    pub(crate) reserved_9_b: [u8; 3],
    pub(crate) word_c: u32,
    pub(crate) word_10: u32,
}

/// Copies one layer input into an initialized 64-byte surface configuration.
///
/// # Safety
///
/// `input` must reference a readable [`LayerConfigInput`] and `config` a
/// writable, four-byte-aligned 64-byte descriptor. `owner` is accepted only to
/// preserve the retailOS three-register ABI and is not dereferenced.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn copy_surface_config(
    _owner: *mut u8,
    input: *const LayerConfigInput,
    config: *mut u8,
) {
    let pixel_format = core::ptr::addr_of!((*input).pixel_format).read_volatile();
    let word_c = core::ptr::addr_of!((*input).word_c).read_volatile();
    let word_10 = core::ptr::addr_of!((*input).word_10).read_volatile();

    config.write_volatile(pixel_format);
    config.add(1).write_volatile(3);
    match pixel_format {
        0 => {
            config.add(0x30).write_volatile(0x10);
            config.add(0x31).write_volatile(0);
            config.add(0x32).write_volatile(0xff);
        }
        2 => (config.add(0x30) as *mut u16).write_volatile(0x1f),
        3 => (config.add(0x30) as *mut u32).write_volatile(0),
        _ => {}
    }
    (config.add(0x10) as *mut u32).write_volatile(word_c);
    (config.add(0x0c) as *mut u32).write_volatile(word_10);
    (config.add(0x18) as *mut u32).write_volatile(word_c);
    (config.add(0x14) as *mut u32).write_volatile(word_10);
    (config.add(0x28) as *mut u32).write_volatile(0);
    (config.add(0x24) as *mut u32).write_volatile(0);
    (config.add(4) as *mut u32).write_volatile(0);
    (config.add(8) as *mut u32).write_volatile(0);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[repr(align(4))]
    struct Config([u8; 64]);

    fn word(config: &Config, offset: usize) -> u32 {
        u32::from_le_bytes(config.0[offset..offset + 4].try_into().unwrap())
    }

    fn input(pixel_format: u8) -> LayerConfigInput {
        LayerConfigInput {
            reserved_0_7: [0; 8],
            pixel_format,
            reserved_9_b: [0; 3],
            word_c: 0x1122_3344,
            word_10: 0x5566_7788,
        }
    }

    #[test]
    fn copies_words_clears_bookkeeping_and_selects_each_format() {
        for (pixel_format, opaque) in [(0, 0xa5ff_0010), (2, 0xa5a5_001f), (3, 0)] {
            let input = input(pixel_format);
            let mut config = Config([0xa5; 64]);
            unsafe { copy_surface_config(core::ptr::null_mut(), &input, config.0.as_mut_ptr()) };

            assert_eq!(config.0[0], pixel_format);
            assert_eq!(config.0[1], 3);
            assert_eq!(word(&config, 0x0c), 0x5566_7788);
            assert_eq!(word(&config, 0x10), 0x1122_3344);
            assert_eq!(word(&config, 0x14), 0x5566_7788);
            assert_eq!(word(&config, 0x18), 0x1122_3344);
            assert_eq!(word(&config, 4), 0);
            assert_eq!(word(&config, 8), 0);
            assert_eq!(word(&config, 0x24), 0);
            assert_eq!(word(&config, 0x28), 0);
            assert_eq!(word(&config, 0x30), opaque);
        }
    }

    #[test]
    fn unknown_format_preserves_opaque_bytes() {
        let input = input(0xff);
        let mut config = Config([0xa5; 64]);
        unsafe { copy_surface_config(core::ptr::null_mut(), &input, config.0.as_mut_ptr()) };

        assert_eq!(config.0[0x30..0x34], [0xa5; 4]);
    }
}
