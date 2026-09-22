//! MPEG audio frame-size calculation — `FUN_08281af4` @ `0x08281af4`.
//!
//! True extent: 172 bytes (`0x08281af4..0x08281b9f`); the two bitrate-table
//! literals at `0x08281ba0` and `0x08281ba4` are followed by the next
//! separately entered function at `0x08281ba8`. Full-image A32 decoding finds
//! three inbound plain `bl` call sites (`0x08281624`, `0x082817ec`, and
//! `0x08281ef4`), zero predicated inbound `bl` call sites, and two plain
//! outgoing `bl` calls to `__rt_udiv` @ `0x08036f14` (one per layer branch),
//! with no predicated outgoing calls.
//!
//! # Algorithm
//!
//! Reject a forbidden bitrate index of 15. Index zero selects the MPEG free
//! bitrate of 128000; all other indices select a per-version bitrate-table
//! entry and scale it by 1000. Divide the bitrate times context `+0x24 >> 3`
//! by the context `+0x18` divisor, add the header padding bit, and multiply
//! by four for layer 1 (`context +0x34 == 1`). Deliberate deviations: host
//! tests replace the two fixed firmware table addresses with fixtures.

use crate::runtime::rt_div::__rt_udiv;

const DIVISOR_OFFSET: usize = 0x18;
const SAMPLE_RATE_SCALE_OFFSET: usize = 0x24;
const BITRATE_TABLE_SELECTOR_OFFSET: usize = 0x30;
const LAYER_OFFSET: usize = 0x34;
const LAYER_ONE: u32 = 1;
const FREE_BITRATE: u32 = 128_000;
const STATUS_INVALID: u32 = 3;
const NONZERO_SELECTOR_BITRATE_TABLE: *const u32 = 0x0897_7aa4 as *const u32;
const ZERO_SELECTOR_BITRATE_TABLE: *const u32 = 0x0897_79f0 as *const u32;

#[cfg(test)]
static mut TEST_NONZERO_SELECTOR_BITRATE_TABLE: *const u32 = core::ptr::null();
#[cfg(test)]
static mut TEST_ZERO_SELECTOR_BITRATE_TABLE: *const u32 = core::ptr::null();

#[inline(always)]
unsafe fn bitrate_table(context: *const u8) -> *const u32 {
    #[cfg(test)]
    {
        if (context.add(BITRATE_TABLE_SELECTOR_OFFSET) as *const i8).read() != 0 {
            TEST_NONZERO_SELECTOR_BITRATE_TABLE
        } else {
            TEST_ZERO_SELECTOR_BITRATE_TABLE
        }
    }
    #[cfg(not(test))]
    {
        if (context.add(BITRATE_TABLE_SELECTOR_OFFSET) as *const i8).read() != 0 {
            NONZERO_SELECTOR_BITRATE_TABLE
        } else {
            ZERO_SELECTOR_BITRATE_TABLE
        }
    }
}

/// Calculates the MPEG audio frame size and stores its bitrate.
///
/// # Safety
///
/// `+0x24`, `+0x30`, and `+0x34`; the selected firmware bitrate table must be
/// valid.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn mpeg_audio_frame_size(
    context: *const u8,
    header: u32,
    bitrate_out: *mut u32,
    frame_size_out: *mut u32,
) -> u32 {
    let bitrate_index = (header >> 12) & 0xf;
    if bitrate_index == 0xf {
        return STATUS_INVALID;
    }

    let layer = (context.add(LAYER_OFFSET) as *const u32).read();
    let bitrate = if bitrate_index == 0 {
        FREE_BITRATE
    } else {
        bitrate_table(context)
            .add((layer.wrapping_sub(1) as usize) * 15 + bitrate_index as usize)
            .read()
            .wrapping_mul(1000)
    };
    bitrate_out.write(bitrate);

    let padding = (header >> 9) & 1;
    let scaled_bitrate = bitrate.wrapping_mul((context.add(SAMPLE_RATE_SCALE_OFFSET) as *const u32).read() >> 3);
    let frame_size = __rt_udiv(scaled_bitrate, (context.add(DIVISOR_OFFSET) as *const u32).read())
        .wrapping_add(padding);
    frame_size_out.write(if layer == LAYER_ONE { frame_size.wrapping_mul(4) } else { frame_size });
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TABLE_LOCK: Mutex<()> = Mutex::new(());

    fn configure_tables(nonzero_selector: &[u32; 30], zero_selector: &[u32; 30]) {
        unsafe {
            TEST_NONZERO_SELECTOR_BITRATE_TABLE = nonzero_selector.as_ptr();
            TEST_ZERO_SELECTOR_BITRATE_TABLE = zero_selector.as_ptr();
        }
    }

    #[test]
    fn rejects_forbidden_bitrate_index_without_outputs() {
        let context = [0u32; 14];
        let mut bitrate = 0xdead_beef;
        let mut frame_size = 0xfeed_face;

        assert_eq!(unsafe { mpeg_audio_frame_size(context.as_ptr().cast(), 0x0000_f000, &mut bitrate, &mut frame_size) }, STATUS_INVALID);
        assert_eq!(bitrate, 0xdead_beef);
        assert_eq!(frame_size, 0xfeed_face);
    }

    #[test]
    fn free_bitrate_uses_fixed_rate_and_layer_one_padding() {
        let _guard = TABLE_LOCK.lock();
        let tables = [0u32; 30];
        configure_tables(&tables, &tables);
        let mut context = [0u32; 14];
        context[DIVISOR_OFFSET / 4] = 25_000;
        context[SAMPLE_RATE_SCALE_OFFSET / 4] = 8;
        context[LAYER_OFFSET / 4] = LAYER_ONE;
        let mut bitrate = 0;
        let mut frame_size = 0;

        assert_eq!(unsafe { mpeg_audio_frame_size(context.as_ptr().cast(), 1 << 9, &mut bitrate, &mut frame_size) }, 0);
        assert_eq!(bitrate, FREE_BITRATE);
        assert_eq!(frame_size, 24);
    }

    #[test]
    fn table_index_and_non_layer_one_size_follow_context() {
        let _guard = TABLE_LOCK.lock();
        let zero_selector = [0u32; 30];
        let mut nonzero_selector = [0u32; 30];
        nonzero_selector[18] = 96;
        configure_tables(&nonzero_selector, &zero_selector);
        let mut context = [0u32; 14];
        context[DIVISOR_OFFSET / 4] = 12_000;
        context[SAMPLE_RATE_SCALE_OFFSET / 4] = 8;
        context[BITRATE_TABLE_SELECTOR_OFFSET / 4] = 1;
        context[LAYER_OFFSET / 4] = 2;
        let mut bitrate = 0;
        let mut frame_size = 0;

        assert_eq!(unsafe { mpeg_audio_frame_size(context.as_ptr().cast(), 3 << 12, &mut bitrate, &mut frame_size) }, 0);
        assert_eq!(bitrate, 96_000);
        assert_eq!(frame_size, 8);
    }

    #[test]
    fn zero_selector_uses_its_own_bitrate_table() {
        let _guard = TABLE_LOCK.lock();
        let mut zero_selector = [0u32; 30];
        zero_selector[1] = 32;
        let nonzero_selector = [0u32; 30];
        configure_tables(&nonzero_selector, &zero_selector);
        let mut context = [0u32; 14];
        context[DIVISOR_OFFSET / 4] = 8_000;
        context[SAMPLE_RATE_SCALE_OFFSET / 4] = 8;
        context[LAYER_OFFSET / 4] = 1;
        let mut bitrate = 0;
        let mut frame_size = 0;

        assert_eq!(unsafe { mpeg_audio_frame_size(context.as_ptr().cast(), 1 << 12, &mut bitrate, &mut frame_size) }, 0);
        assert_eq!(bitrate, 32_000);
        assert_eq!(frame_size, 16);
    }
}
