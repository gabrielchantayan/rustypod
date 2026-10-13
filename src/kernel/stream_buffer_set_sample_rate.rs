//! Sample-rate-dependent RAM stream-buffer sizing.
//!
//! Original `FUN_080071d0` @ `0x080071d0`: 92 bytes (88 bytes of ARM
//! code and the ready-flag literal at +0x58); next function @ `0x0800722c`.
//! Binary-verified calls: one outgoing plain BL, zero predicated BLs;
//! two incoming plain BLs, zero predicated BLs.
//!
//! Select 0x8000 bytes below 22050 Hz, 0x10000 below 32000 Hz, otherwise
//! 0x20000. If word +0x24 differs, store the size, clear the page-ready
//! byte at IRAM mirror 0x2200aed5, and initialize pages with (buffer, 1, 0),
//! forwarding its result. An unchanged size returns zero without writes.
//! No behavioral deviations. Reuses the existing page-initializer seam;
//! host builds use its existing private ready-flag storage.

//! ARM comparison retains both unsigned thresholds, the unchanged-size early
//! return, and ordered size/flag stores. LLVM tail-dispatches through the
//! existing initializer seam rather than emitting the original direct BL.

use super::stream_buffer_initializer::{
    stream_buffer_page_initialize, stream_buffer_state, StreamBufferPageInitialize,
};

#[inline(always)]
unsafe fn set_sample_rate(
    stream_buffer: *mut u8,
    sample_rate: u32,
    ready: *mut u8,
    initialize: StreamBufferPageInitialize,
) -> u32 {
    let size = if sample_rate >= 32000 {
        0x20000
    } else if sample_rate >= 22050 {
        0x10000
    } else {
        0x8000
    };
    let size_word = stream_buffer.cast::<u32>().add(9);
    if core::ptr::read_volatile(size_word) == size {
        return 0;
    }
    core::ptr::write_volatile(size_word, size);
    core::ptr::write_volatile(ready, 0);
    initialize(stream_buffer, 1, 0)
}

/// Select the buffer size for an unsigned sample rate, rebuilding pages only
/// when the size changes.
///
/// # Safety
/// `stream_buffer` must be word-aligned and point to a live retailOS stream
/// buffer (at least 0x150 bytes), valid for the stock page initializer. The
/// caller must serialize access to the buffer and shared page-ready flag.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn stream_buffer_set_sample_rate(
    stream_buffer: *mut u8,
    sample_rate: u32,
) -> u32 {
    let (_, _, ready) = stream_buffer_state();
    set_sample_rate(stream_buffer, sample_rate, ready, stream_buffer_page_initialize())
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn forbidden_initialize(_: *mut u8, _: u32, _: u32) -> u32 {
        panic!("unchanged size must not initialize pages")
    }

    // A local page-initialization model makes rebuilt derived state observable.
    unsafe extern "C" fn initialize_pages(buffer: *mut u8, zero_context: u32, context: u32) -> u32 {
        assert_eq!(zero_context, 1);
        assert_eq!(context, 0);
        let words = buffer.cast::<u32>();
        words.add(1).write(words.read().wrapping_add(words.add(9).read()));
        words.add(5).write(words.add(9).read() >> 1);
        0x8123_4567
    }

    #[test]
    fn unsigned_thresholds_rebuild_derived_state_and_preserve_other_words() {
        for (rate, size) in [
            (0, 0x8000), (22015, 0x8000), (22016, 0x8000),
            (22049, 0x8000), (22050, 0x10000), (31999, 0x10000),
            (32000, 0x20000), (32001, 0x20000), (u32::MAX, 0x20000),
        ] {
            let mut words = [0xa5a5_a5a5u32; 0x150 / 4];
            words[0] = 0x0800_0000;
            let before = words;
            let mut ready = 1;
            let result = unsafe {
                set_sample_rate(words.as_mut_ptr().cast(), rate, &mut ready, initialize_pages)
            };
            assert_eq!(result, 0x8123_4567);
            assert_eq!(ready, 0);
            assert_eq!(words[9], size);
            assert_eq!(words[1], 0x0800_0000 + size);
            assert_eq!(words[5], size / 2);
            for i in 0..words.len() {
                if i != 1 && i != 5 && i != 9 {
                    assert_eq!(words[i], before[i]);
                }
            }
            ready = 0x7f;
            let before = words;
            assert_eq!(unsafe {
                set_sample_rate(words.as_mut_ptr().cast(), rate, &mut ready, forbidden_initialize)
            }, 0);
            assert_eq!(words, before);
            assert_eq!(ready, 0x7f);
        }
    }

    #[test]
    fn rate_changes_within_band_do_not_reinitialize() {
        let mut words = [0u32; 0x150 / 4];
        let mut ready = 1;
        for (size, rates) in [
            (0x8000, [0, 22049]), (0x10000, [22050, 31999]),
            (0x20000, [32000, u32::MAX]),
        ] {
            words[9] = size;
            let before = words;
            for rate in rates {
                assert_eq!(unsafe {
                    set_sample_rate(words.as_mut_ptr().cast(), rate, &mut ready, forbidden_initialize)
                }, 0);
                assert_eq!(words, before);
                assert_eq!(ready, 1);
            }
        }
    }
}
