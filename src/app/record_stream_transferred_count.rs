//! `record_stream_transferred_count` — retailOS `FUN_081d9498`, load address
//! `0x081d9498`, true size 8 bytes.
//!
//! Raw words are `e5900004` (`ldr r0,[r0,#4]`) and `e12fff1e` (`bx lr`).
//! The preceding method returns at `0x081d9494`; the next constructor starts
//! with `push {r4,lr}` at `0x081d94a0`. Whole-image A32 decoding finds two
//! inbound plain BLs (`0x08160964`, `0x081609dc`), zero predicated BLs, and
//! no outgoing calls.
//!
//! Read the stream's accumulated transfer count at target word +1. The
//! constructor at `0x081d94a0` initializes it to zero; methods at `0x081d9408`
//! and `0x081d9450` add their transfer results. The record checker at
//! `0x08160888` compares this count with the record length and subtracts it
//! to obtain the remaining length. No deliberate behavioral deviations;
//! opaque layout is represented by target-width words, not host pointers.

/// Returns the accumulated transfer count without modifying the stream.
///
/// # Safety
/// `stream` must point to at least two aligned, readable `u32` words.
/// There is no NULL check, matching the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.record_stream_transferred_count")]
pub unsafe extern "C" fn record_stream_transferred_count(stream: *const u32) -> u32 {
    unsafe { stream.add(1).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_full_width_count_without_touching_surrounding_state() {
        for count in [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1234_5678] {
            let stream = [0x0898_e0f4, count, 0xdead_beef, !count, 17, 29, 16, 1];
            let before = stream;
            assert_eq!(unsafe { record_stream_transferred_count(stream.as_ptr()) }, count);
            assert_eq!(stream, before);
        }
    }

    #[test]
    fn reads_only_the_second_word_and_observes_updated_counts() {
        let mut stream = [u32::MAX, 0];
        assert_eq!(unsafe { record_stream_transferred_count(stream.as_ptr()) }, 0);
        stream[1] = 37;
        assert_eq!(unsafe { record_stream_transferred_count(stream.as_ptr()) }, 37);
        stream[0] = 0;
        stream[1] = u32::MAX;
        assert_eq!(unsafe { record_stream_transferred_count(stream.as_ptr()) }, u32::MAX);
    }
}
