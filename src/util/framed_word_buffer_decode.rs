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
//! It then transfers the payload to `FUN_082c5f30` @ `0x082c5f30`, which packs
//! the bytes from the end into little-endian target words and trims high zero
//! words. The result is the consumed header-plus-payload byte count with bit
//! 16 cleared, preserving the retail `bic r0, r0, #0x10000` wrap quirk.
//!
//! Deliberate deviation: none. Target builds preserve the unported packer
//! transfer through a literal veneer; host builds expose a volatile callback
//! seam so the boundary and its observable output can be tested.

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

/// ABI of the unported retail payload packer at `0x082c5f30`.
pub type WordBufferPayloadPacker = unsafe extern "C" fn(
    payload: *const u8,
    destination: *mut FramedWordBuffer,
    payload_bytes: u32,
);

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_word_buffer_payload_packer(
    _payload: *const u8,
    _destination: *mut FramedWordBuffer,
    _payload_bytes: u32,
) {
}

/// Host callback replacing the stock payload packer at `0x082c5f30`.
///
/// Read volatily by [`decode_word_buffer_frame`] so test replacements cannot
/// be folded into the caller.
#[cfg(not(target_arch = "arm"))]
pub static mut WORD_BUFFER_PAYLOAD_PACKER: WordBufferPayloadPacker = missing_word_buffer_payload_packer;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn pack_payload(
    payload: *const u8,
    destination: *mut FramedWordBuffer,
    payload_bytes: u32,
) {
    let packer = unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(WORD_BUFFER_PAYLOAD_PACKER))
    };
    unsafe { packer(payload, destination, payload_bytes) };
}

// The payload is relocated away from the stock PC-relative BL range. This
// veneer enters the unported retail packer with the same r0/r1/r2 ABI.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_word_buffer_payload_packer
    .type retail_word_buffer_payload_packer, %function
retail_word_buffer_payload_packer:
    ldr     pc, [pc, #-4]
    .word   0x082c5f30
    .size retail_word_buffer_payload_packer, . - retail_word_buffer_payload_packer
"#
);

#[cfg(target_arch = "arm")]
unsafe extern "C" {
    fn retail_word_buffer_payload_packer(
        payload: *const u8,
        destination: *mut FramedWordBuffer,
        payload_bytes: u32,
    );
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn pack_payload(
    payload: *const u8,
    destination: *mut FramedWordBuffer,
    payload_bytes: u32,
) {
    unsafe { retail_word_buffer_payload_packer(payload, destination, payload_bytes) };
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

    unsafe { pack_payload(frame.add(2), destination, payload_bytes) };
    payload_bytes.wrapping_add(2) & !0x0001_0000
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FRAMED_WORD_BUFFER_DECODE, FIXTURE_LEN).map(|base| base as usize)
    });
    static PACKER_LOCK: Mutex<()> = Mutex::new(());
    static mut PACKER_CALL: Option<(*const u8, *mut FramedWordBuffer, u32)> = None;

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                ptr::write(
                    ptr::addr_of_mut!(WORD_BUFFER_PAYLOAD_PACKER),
                    missing_word_buffer_payload_packer,
                );
                ptr::write(ptr::addr_of_mut!(PACKER_CALL), None);
            }
        }
    }

    unsafe extern "C" fn record_packer(
        payload: *const u8,
        destination: *mut FramedWordBuffer,
        payload_bytes: u32,
    ) {
        unsafe {
            ptr::write(
                ptr::addr_of_mut!(PACKER_CALL),
                Some((payload, destination, payload_bytes)),
            );
        }
    }

    unsafe extern "C" fn model_retail_packer(
        payload: *const u8,
        destination: *mut FramedWordBuffer,
        mut payload_bytes: u32,
    ) {
        if payload_bytes == 0 {
            unsafe { ptr::addr_of_mut!((*destination).word_count).write_volatile(0) };
            return;
        }

        let words = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!((*destination).data)) as usize as *mut u32
        };
        let mut output_word = 0usize;
        let mut source = unsafe { payload.add(payload_bytes as usize - 1) };
        while payload_bytes != 0 {
            let mut word = 0u32;
            let mut byte_index = 0u32;
            while payload_bytes != 0 && byte_index < 4 {
                word |= unsafe { core::ptr::read_volatile(source) as u32 } << (byte_index * 8);
                payload_bytes -= 1;
                source = unsafe { source.sub(1) };
                byte_index += 1;
            }
            unsafe { words.add(output_word).write_volatile(word) };
            output_word += 1;
        }

        while output_word != 0 && unsafe { words.add(output_word - 1).read_volatile() } == 0 {
            output_word -= 1;
        }
        unsafe { ptr::addr_of_mut!((*destination).word_count).write_volatile(output_word as u16) };
    }

    fn fixture() -> Option<*mut u8> {
        let base = *FIXTURE;
        let base = base? as *mut u8;
        unsafe { ptr::write_bytes(base, 0, FIXTURE_LEN) };
        Some(base)
    }

    #[test]
    fn rejects_short_headers_and_out_of_bounds_payloads_without_packing() {
        let _guard = PACKER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let mut destination = FramedWordBuffer { word_count: 0xaaaa, capacity_words: u16::MAX, data: 0 };
        let frame = [0, 1, 0x99];
        unsafe {
            ptr::write(ptr::addr_of_mut!(WORD_BUFFER_PAYLOAD_PACKER), record_packer);
            assert_eq!(decode_word_buffer_frame(frame.as_ptr(), 1, &mut destination), 0);
            assert_eq!(decode_word_buffer_frame(frame.as_ptr(), 2, &mut destination), 0);
            assert_eq!(ptr::read(ptr::addr_of!(PACKER_CALL)), None);
        }
        assert_eq!(destination.word_count, 0xaaaa);
    }

    #[test]
    fn rejects_insufficient_word_capacity_including_empty_frames() {
        let _guard = PACKER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let mut destination = FramedWordBuffer { word_count: 0xaaaa, capacity_words: 1, data: 0 };
        let five_bytes = [0, 5, 1, 2, 3, 4, 5];
        let empty = [0, 0];
        unsafe {
            ptr::write(ptr::addr_of_mut!(WORD_BUFFER_PAYLOAD_PACKER), record_packer);
            assert_eq!(decode_word_buffer_frame(five_bytes.as_ptr(), five_bytes.len() as u32, &mut destination), 0);
            destination.capacity_words = 0;
            assert_eq!(decode_word_buffer_frame(empty.as_ptr(), empty.len() as u32, &mut destination), 0);
            assert_eq!(ptr::read(ptr::addr_of!(PACKER_CALL)), None);
        }
        assert_eq!(destination.word_count, 0xaaaa);
    }

    #[test]
    fn packs_reverse_source_groups_into_little_endian_words() {
        let _guard = PACKER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("util::framed_word_buffer_decode"));
            return;
        };
        let words = unsafe { base.cast::<u32>() };
        let mut destination = FramedWordBuffer {
            word_count: 0xffff,
            capacity_words: 2,
            data: words as usize as u32,
        };
        let frame = [0, 5, 1, 2, 3, 4, 5];
        unsafe {
            ptr::write(ptr::addr_of_mut!(WORD_BUFFER_PAYLOAD_PACKER), model_retail_packer);
            assert_eq!(decode_word_buffer_frame(frame.as_ptr(), frame.len() as u32, &mut destination), 7);
            assert_eq!(destination.word_count, 2);
            assert_eq!(words.read_volatile(), 0x0203_0405);
            assert_eq!(words.add(1).read_volatile(), 1);
        }
    }

    #[test]
    fn zero_payload_clears_count_and_ffffe_payload_wraps_consumed_count() {
        let _guard = PACKER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _reset = Reset;
        let mut empty_destination = FramedWordBuffer { word_count: 7, capacity_words: 1, data: 0 };
        let empty = [0, 0];
        let mut wrapped_destination = FramedWordBuffer { word_count: 0xaaaa, capacity_words: 0x4000, data: 0 };
        let wrapped = [0xff, 0xfe];
        unsafe {
            ptr::write(ptr::addr_of_mut!(WORD_BUFFER_PAYLOAD_PACKER), model_retail_packer);
            assert_eq!(decode_word_buffer_frame(empty.as_ptr(), 2, &mut empty_destination), 2);
            assert_eq!(empty_destination.word_count, 0);
            ptr::write(ptr::addr_of_mut!(WORD_BUFFER_PAYLOAD_PACKER), record_packer);
            assert_eq!(decode_word_buffer_frame(wrapped.as_ptr(), 0x1_0000, &mut wrapped_destination), 0);
            let (payload, destination, payload_bytes) =
                ptr::read(ptr::addr_of!(PACKER_CALL)).expect("accepted frame reaches packer");
            assert_eq!(payload, wrapped.as_ptr().add(2));
            assert_eq!(destination, ptr::addr_of_mut!(wrapped_destination));
            assert_eq!(payload_bytes, 0xfffe);
        }
    }
}
