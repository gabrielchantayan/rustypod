//! `cg_exp_golomb_ue_read` — original: `FUN_082c5df0` @ 0x082c5df0
//! (88 bytes, all code — no literal pool; **50 `bl` call sites**,
//! counted in osos.asm, all in the H.264 decoder's syntax parsers at
//! 0x0836xxxx plus its sibling `se(v)` wrapper `FUN_082c5dcc` @
//! 0x082c5dcc).
//!
//! The H.264 `ue(v)` syntax-element reader: an unsigned Exp-Golomb
//! code word over the decoder's shared RBSP cursor
//! ([`RbspBitReader`]). It lives at 0x082c5df0, inside the Vincent
//! JIT's address block, but it is pure decoder machinery — the three
//! words it touches are the `{data, bit_pos, end}` cursor documented
//! in `crate::h264::bitstream`, and every caller is a syntax parser.
//! It is ported under the `cg_*` roof because that is the cluster the
//! address falls in.
//!
//! Algorithm, exactly as the 22-instruction body has it:
//!
//! ```text
//! leading_zeros = count_leading_zeros(reader, flag)   // 0x0809b040
//! advance(reader, leading_zeros, flag)                // 0x082b3258 (ported)
//! *bits_out = leading_zeros + 1
//! suffix = read_bits(reader, leading_zeros + 1, flag) // 0x082d0630
//! top = 1 << leading_zeros          // ARM register-shift semantics
//! return top + (suffix & ~top) - 1
//! ```
//!
//! which is the textbook `ue(v)` decode `2^n - 1 + suffix`, with the
//! `n + 1`-bit read's mandatory leading `1` masked off instead of
//! skipped. The reader itself never commits the suffix: like every
//! read primitive it leaves `bit_pos` just past the zero prefix, and
//! the CALLER advances `*bits_out` (`n + 1`) afterwards — that is the
//! `FUN_082b3258(param_1, local_10, &local_1c)` trailing every call
//! site. The emulation-prevention flag is passed through verbatim to
//! all three bitstream primitives: the zero-count and the suffix read
//! each report through it when they step over a `00 00 03` byte, and
//! whichever advance runs next pays the 8-bit surcharge.
//!
//! Observable ordering, from the disassembly: the prefix advance runs
//! BEFORE the `*bits_out` store (`str r1,[r5]` follows the first
//! `bl 0x082b3258`), and the store runs BEFORE the suffix read
//! (`bl 0x082d0630`) — a `bits_out` aliasing the flag or cursor would
//! see the intermediate states. The `1 << leading_zeros` shift is the
//! ARM register form (`mov r2, r2, lsl r4`): the amount is the low
//! eight bits of the count, and amounts 32..=255 yield zero (so a
//! degenerate 32-zero prefix returns `0 + suffix - 1`, where
//! `read_bits` itself refuses counts above 32 and returns 0, making
//! the result `0xffff_ffff`). Callers never produce prefixes anywhere
//! near that on conforming streams.
//!
//! Deviations:
//! - `count_leading_zeros` @ 0x0809b040 and `read_bits` @ 0x082d0630
//!   are unported and sit behind the [`CG_EXP_GOLOMB_OPS`]
//!   `read_volatile` dispatch seam (the house pattern — see
//!   `super::heap::CG_HEAP_OPS`). The defaults are `missing_*`
//!   spin-loop stubs, matching `super::timer_wait::CG_TIMER_WAIT_OPS`;
//!   host tests install faithful transcriptions of the originals.
//! - `h264_bitstream_advance` @ 0x082b3258 IS ported and takes a
//!   direct call, per the house convention that a ported callee
//!   retires its seam.
//! - Additions wrap (`wrapping_add`/`wrapping_sub`), matching the
//!   original's `add`/`sub`; a debug build must not panic where the
//!   ARM body wraps.

use crate::h264::bitstream::{h264_bitstream_advance, RbspBitReader};

/// Indirect dispatch for the two unported bitstream primitives (see
/// the module header). Host tests replace the whole table.
#[derive(Clone, Copy)]
pub struct CgExpGolombOps {
    /// `count_leading_zeros` @ 0x0809b040: count the zero bits from the
    /// cursor to the next `1` (the Exp-Golomb prefix), WITHOUT moving
    /// the cursor; reports through the flag when it steps over an
    /// emulation-prevention byte.
    pub count_leading_zeros:
        unsafe extern "C" fn(reader: *mut RbspBitReader, emulation_byte_pending: *mut u8) -> u32,
    /// `read_bits` @ 0x082d0630: return the next `count` bits (1..=32;
    /// anything else yields 0) MSB-first WITHOUT moving the cursor;
    /// clears the flag on entry, sets it when it steps over an
    /// emulation-prevention byte.
    pub read_bits: unsafe extern "C" fn(
        reader: *mut RbspBitReader,
        count: i32,
        emulation_byte_pending: *mut u8,
    ) -> u32,
}

unsafe extern "C" fn missing_count_leading_zeros(
    _reader: *mut RbspBitReader,
    _emulation_byte_pending: *mut u8,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

unsafe extern "C" fn missing_read_bits(
    _reader: *mut RbspBitReader,
    _count: i32,
    _emulation_byte_pending: *mut u8,
) -> u32 {
    loop {
        core::hint::spin_loop();
    }
}

/// The active callee bindings. Unwired `missing_*` stubs until the two
/// primitives are ported (see the module header's deviation); host
/// tests replace the table.
pub static mut CG_EXP_GOLOMB_OPS: CgExpGolombOps = CgExpGolombOps {
    count_leading_zeros: missing_count_leading_zeros,
    read_bits: missing_read_bits,
};

/// Volatile read of the ops table — without it LLVM constant-folds the
/// indirect calls back to the defaults.
#[inline(always)]
fn cg_exp_golomb_ops() -> CgExpGolombOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(CG_EXP_GOLOMB_OPS)) }
}

/// ARM register-shift semantics for `mov r2, #1; mov r2, r2, lsl r4`:
/// the amount is the low eight bits of `amount`, and 32..=255 yields
/// zero. A debug Rust build would reject the out-of-range shift the
/// original takes in stride.
fn arm_lsl_one(amount: u32) -> u32 {
    let n = amount & 0xff;
    if n >= 32 {
        0
    } else {
        1u32 << n
    }
}

/// cg_exp_golomb_ue_read — original: `FUN_082c5df0` @ 0x082c5df0
/// (88 bytes, 50 `bl` call sites).
///
/// Decodes one H.264 `ue(v)` Exp-Golomb element from the cursor:
/// counts the zero prefix `n`, commits exactly those `n` bits, stores
/// `n + 1` to `bits_out` (the count the CALLER advances after the
/// read), reads the `n + 1`-bit suffix word, and returns
/// `(1 << n) + (suffix & ~(1 << n)) - 1` — i.e. `2^n - 1 + suffix`.
/// The cursor is left just past the prefix; the emulation-prevention
/// flag is passed through to every primitive untouched.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cg_exp_golomb_ue_read(
    reader: *mut RbspBitReader,
    bits_out: *mut i32,
    emulation_byte_pending: *mut u8,
) -> u32 {
    let ops = cg_exp_golomb_ops();
    let leading_zeros = (ops.count_leading_zeros)(reader, emulation_byte_pending);
    h264_bitstream_advance(reader, leading_zeros as i32, emulation_byte_pending);
    let bit_count = leading_zeros.wrapping_add(1);
    bits_out.write(bit_count as i32);
    let suffix = (ops.read_bits)(reader, bit_count as i32, emulation_byte_pending);
    let top_bit = arm_lsl_one(leading_zeros);
    top_bit
        .wrapping_add(suffix & !top_bit)
        .wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the shared ops table across tests.
    static LOCK: Mutex<()> = Mutex::new(());

    // ----- Controlled-mock scaffolding (glue tests) -----

    /// One recorded seam call: a tag, the `count` argument (read_bits
    /// only), the flag pointer, and the value `*bits_out` held while
    /// the call ran (ordering probe — the original stores `n + 1`
    /// between the advance and the suffix read).
    type Record = (&'static str, i32, usize, i32);

    static mut CALLS: Vec<Record> = Vec::new();
    static mut SCRIPT_LZ: u32 = 0;
    static mut SCRIPT_SUFFIX: u32 = 0;
    static mut SCRIPT_FLAG_ON_READ: u8 = 0;

    /// The sentinel `bits_out` is initialized to; the lz mock asserts
    /// it is still there (the store follows the prefix advance).
    const BITS_OUT_SENTINEL: i32 = -0x5ead;

    unsafe fn record(tag: &'static str, count: i32, flag: *mut u8, bits_out: *mut i32) {
        (*core::ptr::addr_of_mut!(CALLS)).push((tag, count, flag as usize, bits_out.read()));
    }

    static mut BITS_OUT_FOR_MOCKS: *mut i32 = core::ptr::null_mut();

    unsafe extern "C" fn mock_count_leading_zeros(
        _reader: *mut RbspBitReader,
        flag: *mut u8,
    ) -> u32 {
        record("lz", 0, flag, *core::ptr::addr_of!(BITS_OUT_FOR_MOCKS));
        flag.write(0); // the original clears the flag on entry
        *core::ptr::addr_of!(SCRIPT_LZ)
    }

    unsafe extern "C" fn mock_read_bits(
        _reader: *mut RbspBitReader,
        count: i32,
        flag: *mut u8,
    ) -> u32 {
        record("read", count, flag, *core::ptr::addr_of!(BITS_OUT_FOR_MOCKS));
        // The original clears the flag on entry, then reports.
        flag.write(*core::ptr::addr_of!(SCRIPT_FLAG_ON_READ));
        *core::ptr::addr_of!(SCRIPT_SUFFIX)
    }

    const MOCK_OPS: CgExpGolombOps = CgExpGolombOps {
        count_leading_zeros: mock_count_leading_zeros,
        read_bits: mock_read_bits,
    };

    fn setup_mocks(lz: u32, suffix: u32) -> MutexGuard<'static, ()> {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::addr_of_mut!(SCRIPT_LZ).write(lz);
            core::ptr::addr_of_mut!(SCRIPT_SUFFIX).write(suffix);
            core::ptr::addr_of_mut!(SCRIPT_FLAG_ON_READ).write(0);
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(MOCK_OPS);
        }
        guard
    }

    fn teardown() {
        unsafe {
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(CgExpGolombOps {
                count_leading_zeros: missing_count_leading_zeros,
                read_bits: missing_read_bits,
            });
        }
    }

    fn calls() -> Vec<Record> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// A reader over a scratch payload large enough that the ported
    /// `h264_bitstream_advance` bounds test never fires (its verdict is
    /// discarded by the glue anyway).
    fn scratch_reader(bit_pos: i32) -> (std::vec::Vec<u8>, RbspBitReader) {
        let buf = std::vec![0u8; 4096];
        let reader = RbspBitReader {
            data: buf.as_ptr(),
            bit_pos,
            end: unsafe { buf.as_ptr().add(buf.len()) },
        };
        (buf, reader)
    }

    /// Reference for the return fold, including ARM shift semantics.
    fn reference_fold(lz: u32, suffix: u32) -> u32 {
        let top = arm_lsl_one(lz);
        top.wrapping_add(suffix & !top).wrapping_sub(1)
    }

    #[test]
    fn folds_prefix_and_suffix_like_the_original() {
        let lzs = [
            0u32, 1, 2, 3, 7, 8, 15, 16, 30, 31, 32, 33, 64, 255, 0xffff_ffff,
        ];
        let suffixes = [0u32, 1, 0xffff_ffff, 0xaaaa_5555, 0x8000_0000, 0x0001_0203];
        for lz in lzs {
            for suffix in suffixes {
                let _g = setup_mocks(lz, suffix);
                let (_buf, mut reader) = scratch_reader(40);
                let mut bits_out = BITS_OUT_SENTINEL;
                let mut flag = 0xA5u8;
                unsafe {
                    core::ptr::addr_of_mut!(BITS_OUT_FOR_MOCKS).write(&mut bits_out);
                    let result = cg_exp_golomb_ue_read(&mut reader, &mut bits_out, &mut flag);
                    assert_eq!(
                        result,
                        reference_fold(lz, suffix),
                        "lz={lz:#x} suffix={suffix:#x}"
                    );
                    assert_eq!(bits_out, lz.wrapping_add(1) as i32, "bits_out");
                    // The prefix advance commits exactly `lz` bits; the
                    // suffix is left for the caller.
                    assert_eq!(reader.bit_pos, 40 + lz as i32, "cursor");
                }
                let log = calls();
                assert_eq!(log.len(), 2, "lz then read, nothing else");
                assert_eq!(log[0].0, "lz");
                assert_eq!(log[1].0, "read");
                assert_eq!(log[1].1, lz.wrapping_add(1) as i32, "read count");
                teardown();
            }
        }
    }

    #[test]
    fn orders_store_between_advance_and_suffix_read() {
        let _g = setup_mocks(5, 0x3f);
        let (_buf, mut reader) = scratch_reader(0);
        let mut bits_out = BITS_OUT_SENTINEL;
        let mut flag = 0u8;
        unsafe {
            core::ptr::addr_of_mut!(BITS_OUT_FOR_MOCKS).write(&mut bits_out);
            cg_exp_golomb_ue_read(&mut reader, &mut bits_out, &mut flag);
        }
        let log = calls();
        // The lz mock runs before the `str r1,[r5]`: sentinel intact.
        assert_eq!(log[0].3, BITS_OUT_SENTINEL, "store follows lz count");
        // The suffix read runs after it: `n + 1` already visible.
        assert_eq!(log[1].3, 6, "store precedes suffix read");
        teardown();
    }

    #[test]
    fn passes_flag_pointer_through_and_leaves_it_pending() {
        let _g = setup_mocks(3, 0);
        unsafe {
            core::ptr::addr_of_mut!(SCRIPT_FLAG_ON_READ).write(1);
        }
        let (_buf, mut reader) = scratch_reader(8);
        let mut bits_out = 0i32;
        let mut flag = 0u8;
        let flag_addr = &mut flag as *mut u8 as usize;
        unsafe {
            core::ptr::addr_of_mut!(BITS_OUT_FOR_MOCKS).write(&mut bits_out);
            cg_exp_golomb_ue_read(&mut reader, &mut bits_out, &mut flag);
            // The lz mock cleared the flag, so the prefix advance
            // commits exactly 3 bits; the suffix read then set the
            // flag and NOTHING in the glue consumes it — the caller's
            // own advance pays the surcharge.
            assert_eq!(flag, 1, "suffix EP report stays pending");
            // The advance consumed the flag state at its time (clear),
            // so the prefix commit is exactly 3 bits.
            assert_eq!(reader.bit_pos, 8 + 3);
        }
        for rec in calls() {
            assert_eq!(rec.2, flag_addr, "verbatim flag pointer");
        }
        teardown();
    }

    #[test]
    fn prefix_advance_pays_ep_surcharge() {
        // The lz primitive reporting an EP byte must reach the ported
        // advance through the shared flag: 8 extra bits on the commit.
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe extern "C" fn mock_lz_with_ep(_reader: *mut RbspBitReader, flag: *mut u8) -> u32 {
            flag.write(1); // stepped over a 00 00 03
            4
        }
        unsafe {
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(CgExpGolombOps {
                count_leading_zeros: mock_lz_with_ep,
                read_bits: mock_read_bits,
            });
            core::ptr::addr_of_mut!(SCRIPT_FLAG_ON_READ).write(0);
            core::ptr::addr_of_mut!(SCRIPT_SUFFIX).write(0);
            let (_buf, mut reader) = scratch_reader(16);
            let mut bits_out = 0i32;
            let mut flag = 0u8;
            core::ptr::addr_of_mut!(BITS_OUT_FOR_MOCKS).write(&mut bits_out);
            cg_exp_golomb_ue_read(&mut reader, &mut bits_out, &mut flag);
            assert_eq!(reader.bit_pos, 16 + 4 + 8, "lz + EP surcharge");
            assert_eq!(flag, 0, "advance consumed the flag");
        }
        teardown();
        drop(guard);
    }

    // ----- Faithful-model seams (end-to-end tests) -----
    //
    // Transcriptions of the two unported primitives and the emulation
    // probe 0x082c319c, operating straight on the RbspBitReader words.

    /// `FUN_082c319c` @ 0x082c319c: is the byte at `p` the `0x03` of a
    /// `00 00 03 xx` sequence with `xx < 4`, with at least one byte
    /// after it before `end`? Reads `p[-2]`, so test payloads are
    /// padded (with 0xff, which can never match).
    unsafe fn model_probe(p: *const u8, end: *const u8) -> bool {
        if p.add(1) < end {
            if p.offset(-2).read() == 0
                && p.offset(-1).read() == 0
                && p.read() == 3
                && p.add(1).read() < 4
            {
                return true;
            }
        }
        false
    }

    /// The whole-byte loop of `FUN_0809b040`, entered either after the
    /// first partial byte's zeros (`first == false`: step to the next
    /// byte and probe) or through the `iVar7 == 0` goto
    /// (`first == true`: straight at the current byte).
    unsafe fn model_lz_byte_loop(
        mut p: *const u8,
        end: *const u8,
        flag: *mut u8,
        mut pending_skip: bool,
        mut count: u32,
        mut first: bool,
    ) -> u32 {
        loop {
            if !first {
                p = p.add(1);
                if model_probe(p, end) {
                    pending_skip = true;
                    flag.write(1);
                }
            }
            first = false;
            // LAB_0809b0f0:
            if pending_skip {
                p = p.add(1);
            }
            let mut byte = p.read();
            if pending_skip {
                pending_skip = false;
            }
            let mut i = 0;
            loop {
                if byte & 0x80 != 0 {
                    return count;
                }
                i += 1;
                byte = byte << 1;
                count += 1;
                if i >= 8 {
                    break;
                }
            }
        }
    }

    /// `FUN_0809b040` @ 0x0809b040: leading-zero count, cursor unmoved.
    unsafe extern "C" fn model_count_leading_zeros(
        reader: *mut RbspBitReader,
        flag: *mut u8,
    ) -> u32 {
        let (data, pos, end) = {
            let r = &*reader;
            (r.data, r.bit_pos, r.end)
        };
        flag.write(0);
        let mut p = data.wrapping_offset((pos >> 3) as isize);
        let i7: i32 = 8 - (pos - (pos & !7));
        let mut count: u32 = 0;
        let mut goto_lab = false;
        if i7 == 8 {
            if model_probe(p, end) {
                p = p.add(1);
                flag.write(1);
            }
        } else if i7 == 0 {
            goto_lab = true;
        }
        if goto_lab {
            return model_lz_byte_loop(p, end, flag, false, count, true);
        }
        let mut window: u32 = ((p.read() as u32) << ((8 - i7) as u32 & 0xff)) & 0xff;
        let mut i4: i32 = 0;
        loop {
            if i7 <= i4 {
                return model_lz_byte_loop(p, end, flag, false, count, false);
            }
            if window & 0x80 != 0 {
                return count;
            }
            window = (window & 0x7f) << 1;
            count += 1;
            i4 += 1;
        }
    }

    /// `FUN_082d0630` @ 0x082d0630: read 1..=32 bits, cursor unmoved.
    unsafe extern "C" fn model_read_bits(
        reader: *mut RbspBitReader,
        count: i32,
        flag: *mut u8,
    ) -> u32 {
        let (data, pos, end) = {
            let r = &*reader;
            (r.data, r.bit_pos, r.end)
        };
        flag.write(0);
        if count > 0x20 || count < 1 {
            return 0;
        }
        let mut p = data.wrapping_offset((pos >> 3) as isize);
        let first_bits: i32 = 8 - (pos - (pos & !7));
        if first_bits == 8 && model_probe(p, end) {
            p = p.add(1);
            flag.write(1);
        }
        if first_bits < count {
            let mut next = p.add(1);
            let mut byte = p.read();
            let probed = model_probe(next, end);
            let mut skip_next = probed;
            let low = (8 - first_bits) as u32 & 0xff;
            let mut value: u32 = (((byte as u32) << low) & 0xff) >> low;
            let mut remaining: i32 = count - first_bits;
            if skip_next {
                flag.write(1);
            }
            loop {
                if remaining == 0 {
                    return value;
                }
                if remaining < 8 {
                    break;
                }
                let mut cur = next;
                if skip_next {
                    cur = next.add(1);
                }
                next = cur.add(1);
                byte = cur.read();
                if skip_next {
                    skip_next = false;
                }
                let probed = model_probe(next, end);
                if probed {
                    skip_next = true;
                }
                value = value << 8 | byte as u32;
                remaining -= 8;
                if probed {
                    flag.write(1);
                }
            }
            if skip_next {
                next = next.add(1);
            }
            let rem = remaining as u32 & 0xff;
            return value << rem | (next.read() as u32) >> ((8 - remaining) as u32 & 0xff);
        }
        let low = (8 - first_bits) as u32 & 0xff;
        (((p.read() as u32) << low) & 0xff) >> ((8 - count) as u32 & 0xff)
    }

    const MODEL_OPS: CgExpGolombOps = CgExpGolombOps {
        count_leading_zeros: model_count_leading_zeros,
        read_bits: model_read_bits,
    };

    /// Scratch payload with two 0xff guard bytes before `data` (the
    /// probe reads `p[-2]`) and slack after, so out-of-payload reads
    /// never fault and never false-positive an EP sequence.
    struct Payload {
        buf: std::vec::Vec<u8>,
    }

    impl Payload {
        fn new(bytes: &[u8]) -> Payload {
            let mut buf = std::vec![0xffu8; 2];
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&[0xffu8; 64]);
            Payload { buf }
        }

        fn reader(&self) -> RbspBitReader {
            let data = unsafe { self.buf.as_ptr().add(2) };
            RbspBitReader {
                data,
                bit_pos: 0,
                end: unsafe { data.add(self.buf.len() - 2 - 64) },
            }
        }
    }

    /// Standard H.264 emulation prevention: after two zero bytes,
    /// insert 0x03 before a byte in 0..=3.
    fn insert_emulation_prevention(ebsp: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        let mut zeros = 0;
        for &b in ebsp {
            if zeros >= 2 && b <= 3 {
                out.push(0x03);
                zeros = 0;
            }
            out.push(b);
            zeros = if b == 0 { zeros + 1 } else { 0 };
        }
        out
    }

    /// Is raw byte `i` an inserted emulation-prevention byte (same
    /// predicate the encoder side used)?
    fn is_ep_byte(raw: &[u8], i: usize) -> bool {
        i >= 2 && raw[i - 2] == 0 && raw[i - 1] == 0 && raw[i] == 3 && raw[i + 1] < 4
    }

    /// Strip emulation-prevention bytes: the RBSP the reference
    /// decoder works on.
    fn rbsp_of(raw: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::new();
        for i in 0..raw.len() {
            let last = i + 1 == raw.len();
            if !last && is_ep_byte(raw, i) {
                continue;
            }
            out.push(raw[i]);
        }
        out
    }

    /// Independent naive `ue(v)` decode over the RBSP: returns the
    /// value and the element's length in bits.
    fn reference_ue(rbsp: &[u8], bit_pos: usize) -> (u32, usize) {
        let mut lz = 0usize;
        loop {
            let byte = rbsp[(bit_pos + lz) >> 3];
            if (byte >> (7 - ((bit_pos + lz) & 7))) & 1 == 1 {
                break;
            }
            lz += 1;
        }
        let mut suffix = 0u32;
        for k in 0..lz {
            let pos = bit_pos + lz + 1 + k;
            suffix = suffix << 1 | (rbsp[pos >> 3] >> (7 - (pos & 7))) as u32 & 1;
        }
        ((1u32 << lz) - 1 + suffix, 2 * lz + 1)
    }

    /// Pack `ue(v)` code words for `values` MSB-first, starting at
    /// `start_bit`; returns the payload and the total bit length.
    fn pack_ue_words(values: &[u32], start_bit: usize) -> (std::vec::Vec<u8>, usize) {
        let mut bits = std::vec::Vec::new();
        for _ in 0..start_bit {
            bits.push(0u8);
        }
        for &v in values {
            let code_num = v + 1;
            let lz = 31 - code_num.leading_zeros() as usize;
            for _ in 0..lz {
                bits.push(0u8);
            }
            for k in (0..=lz).rev() {
                bits.push(((code_num >> k) & 1) as u8);
            }
        }
        let total = bits.len();
        let mut bytes = std::vec![0u8; total.div_ceil(8)];
        for (i, b) in bits.iter().enumerate() {
            bytes[i >> 3] |= b << (7 - (i & 7));
        }
        (bytes, total)
    }

    /// Decode `values.len()` elements with the port (plus the caller
    /// side's advance) and check every observable against the naive
    /// RBSP reference.
    fn decode_and_compare(payload: &Payload, values: &[u32], start_bit: i32, rbsp: &[u8]) {
        let mut reader = payload.reader();
        reader.bit_pos = start_bit;
        let mut flag = 0u8;
        let mut rbsp_pos = start_bit as usize;
        for (idx, &expected) in values.iter().enumerate() {
            let mut bits_out = 0i32;
            let got = unsafe {
                let value = cg_exp_golomb_ue_read(&mut reader, &mut bits_out, &mut flag);
                // The caller side of the contract: advance n + 1.
                h264_bitstream_advance(&mut reader, bits_out, &mut flag);
                value
            };
            let (want, len) = reference_ue(rbsp, rbsp_pos);
            assert_eq!(got, expected, "value {idx}");
            assert_eq!(want, expected, "reference sanity, value {idx}");
            assert_eq!(bits_out as usize, (len - 1) / 2 + 1, "bits_out {idx}");
            rbsp_pos += len;
        }
    }

    #[test]
    fn decodes_known_ue_words_byte_aligned() {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(MODEL_OPS);
        }
        let values: std::vec::Vec<u32> = (0..=40).chain([255, 256, 1000, 65_535]).collect();
        let (bytes, _total) = pack_ue_words(&values, 0);
        let payload = Payload::new(&bytes);
        let rbsp = rbsp_of(&bytes); // no EP insertion here: rbsp == bytes
        assert_eq!(rbsp, bytes);
        decode_and_compare(&payload, &values, 0, &rbsp);
        teardown();
        drop(guard);
    }

    #[test]
    fn decodes_across_emulation_prevention_bytes() {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(MODEL_OPS);
        }
        // Long zero prefixes guarantee 00 00 xx byte triples.
        let values: std::vec::Vec<u32> = (0..=20)
            .chain([100, 1000, 1001, 65_535, 65_536, 1_000_000])
            .collect();
        let (ebsp, _total) = pack_ue_words(&values, 0);
        let raw = insert_emulation_prevention(&ebsp);
        let inserted = raw.len() - ebsp.len();
        assert!(inserted > 0, "test must actually exercise EP bytes");
        let payload = Payload::new(&raw);
        let rbsp = rbsp_of(&raw);
        assert_eq!(rbsp, ebsp, "rbsp round-trip");
        decode_and_compare(&payload, &values, 0, &rbsp);
        // Every inserted EP byte is skipped exactly once per forward
        // pass: the cursor ends at the raw position matching the rbsp
        // end.
        teardown();
        drop(guard);
    }

    #[test]
    fn decodes_from_a_misaligned_start() {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(CG_EXP_GOLOMB_OPS).write(MODEL_OPS);
        }
        let values: std::vec::Vec<u32> = (0..=30).collect();
        let (bytes, _total) = pack_ue_words(&values, 5);
        let payload = Payload::new(&bytes);
        decode_and_compare(&payload, &values, 5, &bytes);
        teardown();
        drop(guard);
    }
}
