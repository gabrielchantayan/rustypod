//! `decode_word_buffer_frame` — validate and unpack a big-endian length-prefixed
//! payload into a target-word buffer.
//!
//! Original: `FUN_082bdef0` @ `0x082bdef0` (124 bytes exactly,
//! `0x082bdef0..0x082bdf6c`; the next separately linked function starts at
//! `0x082bdf6c`). A complete decode of every ARM `B`/`BL` word in `osos.dec`
//! finds **six direct, unconditional `bl` call sites** (0x080d4200,
//! 0x082bdf84, 0x082bdfa4, 0x082be010, 0x082be038, and 0x082be058); there are
//! no predicated direct calls.
//!
//! The first two input bytes form a big-endian payload length. The frame is
//! rejected unless its header and full payload fit in `available`, and unless
//! `destination.capacity_words` has at least one word for an empty payload or
//! can contain `ceil(payload_bytes / 4)` words otherwise.
//! It then transfers the payload to `word_list_assign_be_bytes`, which packs
//! the bytes from the end into little-endian target words and trims high zero
//! words. The result is the consumed header-plus-payload byte count with bit
//! 16 cleared, preserving the retail `bic r0, r0, #0x10000` wrap quirk.
//!
//! Deliberate deviation: none.

/// Target-layout destination consumed by `FUN_082c5f30`.
///
/// The stock packer stores the resulting word count at +0x00, validates this
/// capacity field at +0x02, and dereferences the target-width data word at
/// +0x04. Keeping `data` as `u32` retains those offsets on 64-bit hosts.
#[repr(C)]
pub struct FramedWordBuffer {
    pub word_count: u16,
    pub capacity_words: u16,
    pub data: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(FramedWordBuffer, word_count)];
const _: [u8; 0x02] = [0; core::mem::offset_of!(FramedWordBuffer, capacity_words)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(FramedWordBuffer, data)];
const _: [u8; 0x08] = [0; core::mem::size_of::<FramedWordBuffer>()];

/// word_list_assign_be_bytes — original: `FUN_082c5f30` @ `0x082c5f30`
/// (140 bytes).
///
/// Verified extent: the final `b 0x082d27d4` at `0x082c5fb8` makes this a
/// 35-word tail-calling function ending at `0x082c5fbc`; the next function
/// begins with `push {r4-r9, lr}` at `0x082c5fbc`. Decoding every ARM B/BL
/// word in `osos.dec` finds two direct, plain `bl` callers (0x082bdf5c and
/// 0x082d66ec) and zero predicated direct `bl` callers.
///
/// Converts a nonempty big-endian byte sequence into little-endian `u32`
/// limbs by reading from the final byte and filling each limb low byte first.
/// It stores `ceil(payload_bytes / 4)` before tail-calling
/// [`crate::util::word_list::word_list_trim_trailing_zeros`] to drop leading
/// zero input groups. A zero-length sequence only clears `word_count`.
///
/// Deliberate deviation: target builds make the retail tail call directly.
/// Host builds adapt the 32-bit `FramedWordBuffer::data` address into a
/// temporary host-width [`crate::util::word_list::WordList`] for the existing
/// tail-callee, then copy its count back; this preserves the observable data
/// and count without assuming a 64-bit host pointer lives at target offset 4.
///
/// # Safety
///
/// `payload` must name `payload_bytes` readable bytes. For nonzero
/// `payload_bytes`, `destination.data` must be a valid target-width pointer
/// to `ceil(payload_bytes / 4)` writable `u32` limbs; the original does not
/// validate capacity. The practical input domain is at most 65536 bytes:
/// retail decrements its remaining counter through a 16-bit truncation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn word_list_assign_be_bytes(
    payload: *const u8,
    destination: *mut FramedWordBuffer,
    payload_bytes: u32,
) {
    if payload_bytes == 0 {
        (*destination).word_count = 0;
        return;
    }

    let word_count = payload_bytes.wrapping_add(3) >> 2;
    let words = (*destination).data as usize as *mut u32;
    let mut source = payload.add(payload_bytes as usize - 1);
    let mut remaining = payload_bytes as u16;
    let mut output_word = 0u16;

    loop {
        let mut word = 0u32;
        let mut byte_index = 0u16;
        loop {
            remaining = remaining.wrapping_sub(1);
            word |= (core::ptr::read_volatile(source) as u32) << (byte_index * 8);
            source = source.sub(1);
            if remaining == 0 || byte_index.wrapping_add(1) >= 4 {
                break;
            }
            byte_index = byte_index.wrapping_add(1);
        }
        core::ptr::write_volatile(words.add(output_word as usize), word);
        output_word = output_word.wrapping_add(1);
        if remaining == 0 {
            break;
        }
    }

    (*destination).word_count = word_count as u16;
    #[cfg(target_arch = "arm")]
    crate::util::word_list::word_list_trim_trailing_zeros(destination.cast());
    #[cfg(not(target_arch = "arm"))]
    {
        let mut list = crate::util::word_list::WordList {
            count: (*destination).word_count,
            capacity: (*destination).capacity_words,
            entries: words,
        };
        crate::util::word_list::word_list_trim_trailing_zeros(&mut list);
        (*destination).word_count = list.count;
    }
}

/// Validates and unpacks one big-endian-length-prefixed word-buffer frame.
///
/// Original: `FUN_082bdef0` @ `0x082bdef0` (124 bytes; six unconditional
/// direct `bl` callers). The caller must provide at least `available` readable
/// bytes at `frame`; when the result is nonzero, the retail packer requires
/// that `destination` name a valid writable [`FramedWordBuffer`] and that its
/// target-width `data` field identify at least one writable word for an empty
/// payload, or `ceil(payload_bytes / 4)` writable words otherwise. Like
/// retailOS, this function has no NULL guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn decode_word_buffer_frame(
    frame: *const u8,
    available: u32,
    destination: *mut FramedWordBuffer,
) -> u32 {
    if available < 2 {
        return 0;
    }

    let payload_bytes = unsafe {
        u16::from_be_bytes([
            core::ptr::read_volatile(frame),
            core::ptr::read_volatile(frame.add(1)),
        ]) as u32
    };
    let remaining = available.wrapping_sub(2) & 0xffff;
    if payload_bytes > remaining {
        return 0;
    }

    let required_words = if payload_bytes == 0 {
        1
    } else {
        payload_bytes.wrapping_add(3) >> 2
    };
    let capacity_words = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!((*destination).capacity_words)) as u32
    };
    if capacity_words < required_words {
        return 0;
    }

    unsafe { word_list_assign_be_bytes(frame.add(2), destination, payload_bytes) };
    payload_bytes.wrapping_add(2) & !0x0001_0000
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::WORD_LIST_ASSIGN_BE_BYTES, FIXTURE_LEN).map(|base| base as usize)
    });

    fn fixture() -> Option<*mut u8> {
        let base = *FIXTURE;
        let base = base? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some(base)
    }

    #[test]
    fn rejects_short_headers_and_out_of_bounds_payloads_without_packing() {
        let mut destination = FramedWordBuffer { word_count: 0xaaaa, capacity_words: u16::MAX, data: 0 };
        let frame = [0, 1, 0x99];
        unsafe {
            assert_eq!(decode_word_buffer_frame(frame.as_ptr(), 1, &mut destination), 0);
            assert_eq!(decode_word_buffer_frame(frame.as_ptr(), 2, &mut destination), 0);
        }
        assert_eq!(destination.word_count, 0xaaaa);
    }

    #[test]
    fn rejects_insufficient_word_capacity_including_empty_frames() {
        let mut destination = FramedWordBuffer { word_count: 0xaaaa, capacity_words: 1, data: 0 };
        let five_bytes = [0, 5, 1, 2, 3, 4, 5];
        let empty = [0, 0];
        unsafe {
            assert_eq!(decode_word_buffer_frame(five_bytes.as_ptr(), five_bytes.len() as u32, &mut destination), 0);
            destination.capacity_words = 0;
            assert_eq!(decode_word_buffer_frame(empty.as_ptr(), empty.len() as u32, &mut destination), 0);
        }
        assert_eq!(destination.word_count, 0xaaaa);
    }

    #[test]
    fn packs_reverse_source_groups_and_trims_leading_zero_words() {
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("util::framed_word_buffer_decode"));
            return;
        };
        let words = unsafe { base.cast::<u32>() };
        let mut destination = FramedWordBuffer {
            word_count: 0xffff,
            capacity_words: 3,
            data: words as usize as u32,
        };
        let frame = [0, 9, 0, 0, 0, 0, 1, 2, 3, 4, 5];
        unsafe {
            assert_eq!(decode_word_buffer_frame(frame.as_ptr(), frame.len() as u32, &mut destination), 11);
            assert_eq!(destination.word_count, 2);
            assert_eq!(words.read_volatile(), 0x0203_0405);
            assert_eq!(words.add(1).read_volatile(), 1);
            assert_eq!(words.add(2).read_volatile(), 0);
        }
    }

    #[test]
    fn zero_payload_clears_count() {
        let mut empty_destination = FramedWordBuffer { word_count: 7, capacity_words: 1, data: 0 };
        let empty = [0, 0];
        unsafe {
            assert_eq!(decode_word_buffer_frame(empty.as_ptr(), 2, &mut empty_destination), 2);
            assert_eq!(empty_destination.word_count, 0);
        }
    }
}
