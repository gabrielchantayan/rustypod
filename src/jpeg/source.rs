//! The JPEG decoder's source byte reader.
//!
//! `jpeg_source_read_byte` — original: `FUN_080e7ed4` @ 0x080e7ed4
//! (96 bytes: 92 of code plus the 4-byte state-pointer literal
//! @ 0x080e7f30 — Ghidra's `functions.csv` reports 92 and drops the
//! literal; the next function starts at 0x080e7f34. 60 `bl` call sites
//! and zero predicated or plain `b`, binary-scanned over every branch
//! word in `work/firmware/osos.dec`).
//!
//! # What it is
//!
//! Every byte the JPEG decoder consumes comes through this function. It
//! is the "get the next source byte" primitive of the decoder whose
//! state lives in the single global @ 0x08a0a79c, and the identification
//! is pinned by its callers:
//!
//! - `FUN_0807ec24` @ 0x0807ec24 — the entropy-coded bit reader. On a
//!   `0xff` byte it reads one more and accepts `0xff 0x00` as a literal
//!   `0xff`, flagging error `0xe` for anything else: JPEG byte stuffing.
//! - `FUN_080e9eb4` @ 0x080e9eb4 — `DHT`. Splits each table byte into
//!   `Th = b & 0xf` / `Tc = b >> 4`, allocates a 0x1b4-byte derived
//!   table per entry, files DC tables at `+0x54`/`+0x94` (count `+0x50`)
//!   and AC tables at `+0xd8`/`+0x118` (count `+0xd4`), and stops on the
//!   next `0xff` marker — which it *pushes back* with
//!   `queue = queue << 8 | 0xff; read_pos -= 1`, the one-byte ungetc
//!   that proves `+0x88` is a little-endian byte queue.
//! - `FUN_0807a7b0` @ 0x0807a7b0 — the marker scanner.
//! - `FUN_080769c0` @ 0x080769c0 — two calls back to back: the 16-bit
//!   big-endian segment length.
//!
//! The producer side is `FUN_08086ed0` @ 0x08086ed0: it `memcpy`s
//! 0x400-byte chunks alternately into the two banks (`+0x64`, `+0x68`),
//! tracks its own fill position at `+0x8c`, picks the destination bank
//! with the same bit-10 test used here, and stalls while
//! `fill_pos - read_pos > 0x3ff`. So the two banks form a 2 KiB circular
//! double buffer and this reader is its consumer.
//!
//! # Algorithm
//!
//! ```text
//! pos = read_pos                       ; +0x84, a free-running byte count
//! if (pos & 3) == 0:                   ; at a word boundary, refill
//!     bank = (pos & 0x400) ? bank_odd : bank_even
//!     queue = *(u32 *)(bank + (pos & 0x3ff))
//! b = queue & 0xff
//! read_pos = pos + 1
//! queue >>= 8
//! return b
//! ```
//!
//! `read_pos` is a free-running byte counter, never masked in place:
//! only the buffer index (`pos & 0x3ff`) and the bank select
//! (`pos & 0x400`) are derived from it, which is why callers can decrement
//! it to push a byte back. Because the refill only happens when
//! `pos & 3 == 0`, the word load is always 4-byte aligned.
//!
//! Faithful details:
//! - The original loads `read_pos` twice on the refill path
//!   (`add r0, r3, #0` / `ldr r0, [r0, #0x84]` re-reads what `r1`
//!   already holds) — a redundant ADS reload of the same word, folded to
//!   one read here.
//! - The bank select is `lsls r2, r1, #21` reading the sign bit, i.e.
//!   bit 10 of the position — not a comparison against the fill level.
//!   A position past the end of the 2 KiB window silently aliases back
//!   into it; the producer's `fill - read > 0x3ff` stall is what keeps
//!   that from happening.
//! - No bounds, NULL or end-of-data check exists anywhere in the body.
//!   All 60 call sites are plain `bl` with no predication, so no caller
//!   guards it either: exhaustion is detected by the decoder's own
//!   marker logic, not here.
//!
//! Deviation: the state lives at the fixed address 0x08a0a79c on device
//! and in host test storage otherwise (`cxx/object_flags.rs` precedent).
//! Only the four words this function touches are modeled.

/// Load address of the JPEG decoder's global state (the literal pool
/// word @ 0x080e7f30).
#[cfg(target_os = "none")]
const JPEG_DECODER_STATE: usize = 0x08a0_a79c;

/// Byte offset of the source window inside that state: `bank_even` is
/// the word @ `state + 0x64`.
#[cfg(target_os = "none")]
const SOURCE_WINDOW_OFFSET: usize = 0x64;

/// Size of one bank; also the wrap mask's span (`mov`-free in the
/// original: `lsl #22` / `lsr #22` isolates the low 10 bits).
pub const BANK_SIZE: u32 = 0x400;

/// Buffer index mask — `pos & 0x3ff`.
const BANK_OFFSET_MASK: u32 = BANK_SIZE - 1;

/// Bank select bit — `pos & 0x400`, tested as the sign bit of
/// `pos << 21`.
const BANK_SELECT_BIT: u32 = BANK_SIZE;

/// The four words of the decoder state this reader touches, laid out at
/// their firmware offsets relative to `state + 0x64`.
#[repr(C)]
pub struct JpegSourceWindow {
    /// state +0x64: bank used while `read_pos & 0x400 == 0`.
    pub bank_even: *mut u8,
    /// state +0x68: bank used while `read_pos & 0x400 != 0`.
    pub bank_odd: *mut u8,
    /// state +0x6c..+0x83: marker peek state and friends, untouched here.
    _between: [u32; 6],
    /// state +0x84: free-running source byte position.
    pub read_pos: u32,
    /// state +0x88: up to four buffered bytes, lowest byte first.
    pub queue: u32,
}

// Target-exact layout: the offsets the original's `ldr [r3, #0x64]`,
// `[r3, #0x68]`, `[r3, #0x84]` and `[r3, #0x88]` assume, expressed
// relative to `state + 0x64`.
#[cfg(target_pointer_width = "32")]
mod source_window_layout {
    use super::JpegSourceWindow;
    const _: [u8; 0x00] = [0; core::mem::offset_of!(JpegSourceWindow, bank_even)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(JpegSourceWindow, bank_odd)];
    const _: [u8; 0x20] = [0; core::mem::offset_of!(JpegSourceWindow, read_pos)];
    const _: [u8; 0x24] = [0; core::mem::offset_of!(JpegSourceWindow, queue)];
}

/// Host stand-in for the firmware state @ 0x08a0a79c.
#[cfg(not(target_os = "none"))]
pub static mut HOST_SOURCE_WINDOW: JpegSourceWindow = JpegSourceWindow {
    bank_even: core::ptr::null_mut(),
    bank_odd: core::ptr::null_mut(),
    _between: [0; 6],
    read_pos: 0,
    queue: 0,
};

/// The decoder's source window: `0x08a0a79c + 0x64` on device.
#[inline(always)]
pub unsafe fn source_window() -> *mut JpegSourceWindow {
    #[cfg(target_os = "none")]
    {
        (JPEG_DECODER_STATE + SOURCE_WINDOW_OFFSET) as *mut JpegSourceWindow
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::addr_of_mut!(HOST_SOURCE_WINDOW)
    }
}

/// jpeg_source_read_byte — original: `FUN_080e7ed4` @ 0x080e7ed4
/// (96 bytes).
///
/// Returns the next source byte, zero-extended into `r0`, refilling the
/// four-byte queue from the 2 KiB double buffer at every word boundary.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn jpeg_source_read_byte() -> u32 {
    let window = source_window();

    // Volatile: the banks and the position are shared with the filler
    // task @ 0x08086ed0, which advances `+0x8c` from another thread.
    let position = core::ptr::read_volatile(core::ptr::addr_of!((*window).read_pos));

    if position & 3 == 0 {
        let bank = if position & BANK_SELECT_BIT == 0 {
            core::ptr::read_volatile(core::ptr::addr_of!((*window).bank_even))
        } else {
            core::ptr::read_volatile(core::ptr::addr_of!((*window).bank_odd))
        };
        // Word-aligned by construction: the refill only runs when the
        // position is a multiple of four and each bank is 0x400-aligned.
        let word = bank.add((position & BANK_OFFSET_MASK) as usize).cast::<u32>().read_volatile();
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*window).queue), word);
    }

    let queue = core::ptr::read_volatile(core::ptr::addr_of!((*window).queue));
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*window).read_pos),
        position.wrapping_add(1),
    );
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*window).queue), queue >> 8);

    queue & 0xff
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests that drive the single global window.
    static SOURCE_LOCK: Mutex<()> = Mutex::new(());

    /// A 2 KiB double buffer, 4-byte aligned like the firmware's.
    #[repr(align(4))]
    struct DoubleBuffer([u8; 2 * BANK_SIZE as usize]);

    fn install(buffer: &mut DoubleBuffer, read_pos: u32) -> MutexGuard<'static, ()> {
        let guard = SOURCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let window = source_window();
            (*window).bank_even = buffer.0.as_mut_ptr();
            (*window).bank_odd = buffer.0.as_mut_ptr().add(BANK_SIZE as usize);
            (*window).read_pos = read_pos;
            (*window).queue = 0;
        }
        guard
    }

    fn read_n(count: usize) -> Vec<u32> {
        (0..count).map(|_| unsafe { jpeg_source_read_byte() }).collect()
    }

    fn window_read_pos() -> u32 {
        unsafe { (*source_window()).read_pos }
    }

    fn window_queue() -> u32 {
        unsafe { (*source_window()).queue }
    }

    /// Fills the whole 2 KiB window with `i % 251` so every byte is
    /// distinguishable within a bank and across the bank boundary.
    fn patterned() -> DoubleBuffer {
        let mut buffer = DoubleBuffer([0; 2 * BANK_SIZE as usize]);
        for (index, slot) in buffer.0.iter_mut().enumerate() {
            *slot = (index % 251) as u8;
        }
        buffer
    }

    #[test]
    fn reads_the_even_bank_byte_by_byte_from_a_word_boundary() {
        let mut buffer = patterned();
        let guard = install(&mut buffer, 0);
        assert_eq!(read_n(8), std::vec![0, 1, 2, 3, 4, 5, 6, 7]);
        drop(guard);
    }

    #[test]
    fn a_mid_word_start_uses_the_stale_queue_until_the_next_boundary() {
        // The original only refills when `pos & 3 == 0`, so starting at
        // pos 1 hands back the pre-loaded queue's bytes 1..3 first.
        let mut buffer = patterned();
        let guard = install(&mut buffer, 1);
        unsafe { (*source_window()).queue = 0xdd_cc_bb_aa };
        assert_eq!(read_n(3), std::vec![0xaa, 0xbb, 0xcc]);
        // pos is now 4: the refill takes over from the buffer.
        assert_eq!(read_n(4), std::vec![4, 5, 6, 7]);
        drop(guard);
    }

    #[test]
    fn the_queue_is_little_endian() {
        let mut buffer = DoubleBuffer([0; 2 * BANK_SIZE as usize]);
        buffer.0[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let guard = install(&mut buffer, 0);
        assert_eq!(read_n(4), std::vec![0x11, 0x22, 0x33, 0x44]);
        // The word was loaded whole and shifted down one byte per read.
        assert_eq!(window_queue(), 0);
        drop(guard);
    }

    #[test]
    fn bit_ten_of_the_position_selects_the_odd_bank() {
        let mut buffer = patterned();
        let guard = install(&mut buffer, BANK_SIZE - 4);
        // Last word of the even bank, then the first of the odd one.
        let expected: Vec<u32> = (BANK_SIZE - 4..BANK_SIZE + 4)
            .map(|index| (index as usize % 251) as u32)
            .collect();
        assert_eq!(read_n(8), expected);
        drop(guard);
    }

    #[test]
    fn the_position_wraps_back_into_the_window_after_two_kib() {
        // `pos & 0x3ff` / `pos & 0x400` alias; nothing masks the counter.
        let mut buffer = patterned();
        let guard = install(&mut buffer, 2 * BANK_SIZE);
        assert_eq!(read_n(4), std::vec![0, 1, 2, 3], "0x800 aliases to offset 0 of the even bank");
        drop(guard);
    }

    #[test]
    fn the_position_advances_by_exactly_one_per_call() {
        let mut buffer = patterned();
        let guard = install(&mut buffer, 0x1234_5670);
        for step in 0..9u32 {
            assert_eq!(window_read_pos(), 0x1234_5670 + step);
            unsafe { jpeg_source_read_byte() };
        }
        assert_eq!(window_read_pos(), 0x1234_5679);
        drop(guard);
    }

    #[test]
    fn the_position_wraps_at_u32_without_trapping() {
        let mut buffer = patterned();
        let guard = install(&mut buffer, u32::MAX);
        unsafe { jpeg_source_read_byte() };
        assert_eq!(window_read_pos(), 0);
        drop(guard);
    }

    #[test]
    fn a_pushed_back_byte_is_read_again() {
        // The DHT parser @ 0x080e9eb4 ungets a marker with
        // `queue = queue << 8 | 0xff; read_pos -= 1`.
        let mut buffer = DoubleBuffer([0; 2 * BANK_SIZE as usize]);
        buffer.0[..4].copy_from_slice(&[0x01, 0xff, 0x02, 0x03]);
        let guard = install(&mut buffer, 0);
        assert_eq!(read_n(2), std::vec![0x01, 0xff]);
        unsafe {
            let window = source_window();
            (*window).queue = ((*window).queue << 8) | 0xff;
            (*window).read_pos -= 1;
        }
        assert_eq!(read_n(3), std::vec![0xff, 0x02, 0x03]);
        drop(guard);
    }

    #[test]
    fn every_byte_value_survives_unsign_extended() {
        let mut buffer = DoubleBuffer([0; 2 * BANK_SIZE as usize]);
        for (index, slot) in buffer.0[..256].iter_mut().enumerate() {
            *slot = index as u8;
        }
        let guard = install(&mut buffer, 0);
        let read = read_n(256);
        for (index, value) in read.iter().enumerate() {
            assert_eq!(*value, index as u32, "byte {index}");
            assert!(*value <= 0xff);
        }
        drop(guard);
    }

    #[test]
    fn the_banks_may_be_two_unrelated_regions() {
        // Nothing requires the odd bank to follow the even one; the
        // filler stores two independent pointers.
        let mut even = DoubleBuffer([0xaa; 2 * BANK_SIZE as usize]);
        let mut odd = DoubleBuffer([0xbb; 2 * BANK_SIZE as usize]);
        let guard = SOURCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let window = source_window();
            (*window).bank_even = even.0.as_mut_ptr();
            (*window).bank_odd = odd.0.as_mut_ptr();
            (*window).read_pos = BANK_SIZE - 4;
            (*window).queue = 0;
        }
        assert_eq!(read_n(8), std::vec![0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb]);
        drop(guard);
    }
}
