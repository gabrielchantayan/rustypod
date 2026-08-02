//! Formatting a byte string as colon-separated uppercase hex — the
//! `"01:23:AB"` renderer behind the device's keyid/serial diagnostics.
//!
//! - `blob_to_hex` — original: `FUN_082d2bb8` @ 0x082d2bb8 (160 bytes of
//!   code, plus the literal-pool word @ 0x082d2c58 holding the digit
//!   table pointer). Two `bl` call sites, 0x080aedfc and 0x080aee4c,
//!   both inside the keyid/serial formatter @ 0x080aede0: it loads a
//!   descriptor's length (+0x00) and blob pointer (+0x08), formats them
//!   here, hands the string to the string builder @ 0x0806ea5c under
//!   the labels `"keyid"` / `"serial"`, and releases it through
//!   `traced_free` @ 0x08043994.
//!
//! Algorithm:
//!
//! 1. `blob == NULL || len == 0` returns NULL without touching the heap.
//!    The original folds both tests into flags — `movs r5,r0` then a
//!    predicated `cmpne r4,#0` — so a *negative* `len` passes the guard.
//! 2. Ask [`traced_alloc`] for `len*3 + 1` bytes (`add r0,r4,r4,lsl #1`
//!    then `add r0,r0,#1`, both wrapping) with zero tags.
//! 3. On allocation failure, record the diagnostic triple
//!    (0x22, 0x6f, 0x41) with two zero data words in the per-task ring
//!    buffer @ 0x08049a84 and return NULL.
//! 4. Otherwise emit `digits[b >> 4]`, `digits[b & 0xf]`, `':'` for each
//!    byte, then overwrite the trailing `':'` with the NUL terminator
//!    (`strb r2,[r1,#-1]`) and return the buffer.
//!
//! The block is one byte larger than the string: 2n digits plus n-1
//! separators plus the NUL is 3n bytes, so the last byte of every block
//! stays uninitialized. The port reproduces the `3n + 1` request rather
//! than tightening it.
//!
//! The digit table is reached through the literal-pool pointer @
//! 0x082d2c58 = 0x08a0eddc. Applying the +0xaed8 image/runtime skew
//! documented in `sqlite/mod.rs` puts it at image address 0x08a19cb4,
//! which holds exactly `"0123456789ABCDEF\0\0\0\0"` — the standard
//! uppercase table, modeled here as [`HEX_DIGITS`].
//!
//! `len` stays signed end to end (the loop closes with `cmp r2,r4` /
//! `blt`). For most negative lengths `len*3 + 1` is negative too and
//! `traced_alloc`'s own `size <= 0` guard takes the diagnostic path
//! before any underlying allocator is called. A negative `len` whose
//! `len*3 + 1` *wraps back positive* (e.g. `-0x55555555`) instead
//! allocates, skips the loop entirely, and lands the terminator store
//! one byte **before** the block. That underflow is the original's
//! behavior, reproduced here deliberately rather than papered over; no
//! caller can reach it, since both pass a descriptor length.
//!
//! Register usage: r5 = blob cursor, r4 = len, r0 = block, r1 = output
//! cursor, r2 = index, r3 = scratch byte, ip = digit table, lr = `':'`.
//!
//! Deviations: the ring-buffer logger @ 0x08049a84 is unported (it
//! walks a per-task record block obtained from 0x080498f8 and packs its
//! first three arguments into one word as
//! `a0 << 24 | (a1 & 0xfff) << 12 | (a2 & 0xfff)`), so it sits behind
//! the [`HEX_BLOB_HOOKS`] dispatch seam whose default is a documented
//! no-op — the NULL the caller sees is unchanged either way.
//! [`traced_alloc`] is ported and is called directly, as in the
//! original.

use crate::drivers::ata_cmd::traced_alloc;

/// Runtime address of the digit table the original indexes, from the
/// literal-pool word @ 0x082d2c58. Its contents live at
/// `HEX_DIGITS_ADDRESS + 0xaed8` in the decrypted image (the skew
/// `sqlite/mod.rs` documents).
pub const HEX_DIGITS_ADDRESS: u32 = 0x08a0eddc;

/// The uppercase digit table, verbatim from the image @ 0x08a19cb4. A
/// ROM address a host cannot reproduce, so the port models it as a
/// crate static — the `string_object.rs` precedent for ROM data.
pub static HEX_DIGITS: [u8; 16] = *b"0123456789ABCDEF";

/// The separator the original keeps live in `lr` for the whole loop.
const SEPARATOR: u8 = b':';

/// The diagnostic triple `blob_to_hex` records when the allocation
/// fails: `mov r0,#0x22` / `mov r1,#0x6f` / `mov r2,#0x41`, with both
/// data words zero (`mov r3,#0` and `str r3,[sp]`).
pub const ALLOC_FAILURE_EVENT: (u32, u32, u32) = (0x22, 0x6f, 0x41);

/// The one unported service `blob_to_hex` reaches: the per-task
/// diagnostic ring buffer @ 0x08049a84.
#[derive(Clone, Copy)]
pub struct HexBlobHooks {
    /// `FUN_08049a84`: append one event to the calling task's ring
    /// buffer. The first three arguments are packed into a single word
    /// (`facility << 24 | (subsystem & 0xfff) << 12 | (code & 0xfff)`);
    /// the two data words are stored in parallel arrays at +0xc4 and
    /// +0x104 of the same record block. The fifth argument rides on the
    /// stack in the original (`str r3,[sp]` @ 0x082d2c00).
    pub record_event: unsafe extern "C" fn(
        facility: u32,
        subsystem: u32,
        code: u32,
        data0: u32,
        data1: u32,
    ),
}

/// Default boundary while 0x08049a84 is unported. Dropping the event is
/// the only honest stand-in for a ring buffer that does not exist yet —
/// the original's caller-visible result (NULL) does not depend on it.
unsafe extern "C" fn missing_event_recorder(
    _facility: u32,
    _subsystem: u32,
    _code: u32,
    _data0: u32,
    _data1: u32,
) {
}

/// Wired default for [`HEX_BLOB_HOOKS`].
pub const DEFAULT_HEX_BLOB_HOOKS: HexBlobHooks = HexBlobHooks {
    record_event: missing_event_recorder,
};

/// Active model of the diagnostic call in [`blob_to_hex`]. Host tests
/// replace it to observe the exact triple; a later port of 0x08049a84
/// replaces the default without touching this caller.
pub static mut HEX_BLOB_HOOKS: HexBlobHooks = DEFAULT_HEX_BLOB_HOOKS;

/// Reads the hook slot. Volatile so LLVM cannot constant-fold the load
/// to the no-op default (the house pattern — `cxx/string_object.rs`).
#[inline(always)]
unsafe fn record_event_op() -> unsafe extern "C" fn(u32, u32, u32, u32, u32) {
    core::ptr::read_volatile(core::ptr::addr_of!(HEX_BLOB_HOOKS.record_event))
}

/// blob_to_hex — original: `FUN_082d2bb8` @ 0x082d2bb8 (160 bytes).
///
/// Renders `len` bytes of `blob` as uppercase hex pairs joined by
/// `':'`, into a freshly allocated NUL-terminated string of exactly
/// `len*3 + 1` bytes ("01:23:AB"). Returns NULL for a NULL blob, for
/// `len == 0`, and on allocation failure (which also records the
/// diagnostic triple [`ALLOC_FAILURE_EVENT`]). The caller owns the
/// result and frees it through `traced_free`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn blob_to_hex(blob: *const u8, len: i32) -> *mut u8 {
    // `movs r5,r0` + predicated `cmpne r4,#0`: NULL blob or zero length.
    // A negative length passes, exactly as in the original.
    if blob.is_null() || len == 0 {
        return core::ptr::null_mut();
    }

    // Two hex digits and a separator per byte, plus the terminator that
    // replaces the last separator. Wrapping, and signed all the way into
    // traced_alloc's own `size <= 0` guard.
    let size = len.wrapping_mul(3).wrapping_add(1);
    let out = traced_alloc(size, 0, 0);
    if out.is_null() {
        let (facility, subsystem, code) = ALLOC_FAILURE_EVENT;
        record_event_op()(facility, subsystem, code, 0, 0);
        return core::ptr::null_mut();
    }

    let digits = core::ptr::addr_of!(HEX_DIGITS).cast::<u8>();
    let mut src = blob;
    let mut cursor = out;
    let mut index: i32 = 0;
    // Volatile accesses keep LLVM's loop-idiom pass from rewriting this
    // into a libc call that does not exist on target (PORTING.md).
    while index < len {
        let byte = src.read_volatile();
        index = index.wrapping_add(1);
        cursor.write_volatile(digits.add((byte >> 4) as usize).read());
        cursor = cursor.add(1);
        cursor.write_volatile(digits.add((byte & 0xf) as usize).read());
        cursor = cursor.add(1);
        cursor.write_volatile(SEPARATOR);
        cursor = cursor.add(1);
        src = src.add(1);
    }
    // `strb r2,[r1,#-1]`: the terminator overwrites the last separator.
    cursor.sub(1).write_volatile(0);
    out
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::drivers::ata_cmd::{missing_allocator, TRACED_ALLOC_HOOKS};
    use crate::testing::TRACED_ALLOC_TEST_LOCK;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Byte the mock heap is filled with, so "written" and "untouched"
    /// are distinguishable at every position.
    const POISON: u8 = 0xa5;

    /// One leading guard byte (the negative-length underflow store lands
    /// there) plus room for the largest string the tests format.
    const GUARD: usize = 1;
    const HEAP_CAPACITY: usize = 512;

    static mut MOCK_HEAP: [u8; GUARD + HEAP_CAPACITY] = [POISON; GUARD + HEAP_CAPACITY];
    /// Requests the mock allocator saw, as `(size, tag1, tag2)`.
    static ALLOC_REQUESTS: Mutex<Vec<(i32, u32, u32)>> = Mutex::new(Vec::new());
    /// Events the mock recorder saw.
    static EVENTS: Mutex<Vec<(u32, u32, u32, u32, u32)>> = Mutex::new(Vec::new());
    /// Set to fail every request regardless of size.
    static mut ALLOC_ALWAYS_FAILS: bool = false;

    unsafe extern "C" fn mock_alloc(size: i32, tag1: u32, tag2: u32) -> *mut u8 {
        ALLOC_REQUESTS.lock().unwrap().push((size, tag1, tag2));
        if ALLOC_ALWAYS_FAILS || size <= 0 || size as usize > HEAP_CAPACITY {
            return core::ptr::null_mut();
        }
        core::ptr::addr_of_mut!(MOCK_HEAP).cast::<u8>().add(GUARD)
    }

    unsafe extern "C" fn mock_recorder(a: u32, b: u32, c: u32, d: u32, e: u32) {
        EVENTS.lock().unwrap().push((a, b, c, d, e));
    }

    /// Installs the mocks and restores the shipped defaults on drop.
    /// Holds the crate-wide allocator-hook lock for the whole test, so
    /// these never race `drivers::ata_cmd`'s own allocator tests.
    struct Fixture {
        /// Held for the whole test; never read.
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new(alloc_fails: bool) -> Self {
            let guard = TRACED_ALLOC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            ALLOC_REQUESTS.lock().unwrap().clear();
            EVENTS.lock().unwrap().clear();
            unsafe {
                MOCK_HEAP = [POISON; GUARD + HEAP_CAPACITY];
                ALLOC_ALWAYS_FAILS = alloc_fails;
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).alloc = mock_alloc;
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).trace = None;
                (*core::ptr::addr_of_mut!(HEX_BLOB_HOOKS)).record_event = mock_recorder;
            }
            Fixture { _guard: guard }
        }

        /// The mock heap as the port left it, guard byte included.
        fn heap(&self) -> Vec<u8> {
            unsafe { (*core::ptr::addr_of!(MOCK_HEAP)).to_vec() }
        }

        fn requests(&self) -> Vec<(i32, u32, u32)> {
            ALLOC_REQUESTS.lock().unwrap().clone()
        }

        fn events(&self) -> Vec<(u32, u32, u32, u32, u32)> {
            EVENTS.lock().unwrap().clone()
        }

        /// The formatted string, read up to (and excluding) the NUL.
        fn formatted(&self, result: *mut u8) -> Vec<u8> {
            assert!(!result.is_null(), "expected a formatted string");
            let heap = self.heap();
            let body = &heap[GUARD..];
            let end = body.iter().position(|&b| b == 0).expect("no NUL terminator");
            body[..end].to_vec()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                (*core::ptr::addr_of_mut!(TRACED_ALLOC_HOOKS)).alloc = missing_allocator;
                (*core::ptr::addr_of_mut!(HEX_BLOB_HOOKS)).record_event = missing_event_recorder;
                ALLOC_ALWAYS_FAILS = false;
            }
        }
    }

    /// Reference: uppercase hex pairs joined by ':', NUL-terminated —
    /// what the original writes for any `len >= 1`.
    fn reference(blob: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for byte in blob {
            out.push(HEX_DIGITS[(byte >> 4) as usize]);
            out.push(HEX_DIGITS[(byte & 0xf) as usize]);
            out.push(SEPARATOR);
        }
        if let Some(last) = out.last_mut() {
            *last = 0;
        }
        out
    }

    /// Runs the port over a slice and returns the bytes it produced,
    /// including the terminator.
    fn format(fixture: &Fixture, blob: &[u8]) -> Vec<u8> {
        let result = unsafe { blob_to_hex(blob.as_ptr(), blob.len() as i32) };
        let mut bytes = fixture.formatted(result);
        bytes.push(0);
        bytes
    }

    #[test]
    fn zero_length_returns_null_without_allocating() {
        let fixture = Fixture::new(false);
        let blob = [0x41u8; 4];
        assert!(unsafe { blob_to_hex(blob.as_ptr(), 0) }.is_null());
        assert!(fixture.requests().is_empty(), "the heap must not be touched");
        assert!(fixture.events().is_empty(), "no diagnostic for the guard path");
    }

    #[test]
    fn null_blob_returns_null_without_allocating() {
        let fixture = Fixture::new(false);
        assert!(unsafe { blob_to_hex(core::ptr::null(), 8) }.is_null());
        assert!(fixture.requests().is_empty(), "the heap must not be touched");
        assert!(fixture.events().is_empty());
    }

    #[test]
    fn one_byte_formats_as_a_bare_pair() {
        let fixture = Fixture::new(false);
        assert_eq!(format(&fixture, &[0x0f]), b"0F\0".to_vec());
        assert_eq!(fixture.requests(), std::vec![(4, 0, 0)], "1*3 + 1 bytes, zero tags");
    }

    #[test]
    fn every_byte_value_uses_the_uppercase_table() {
        let fixture = Fixture::new(false);
        for byte in 0u8..=0xff {
            let expected = reference(&[byte]);
            assert_eq!(format(&fixture, &[byte]), expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn high_bit_bytes_keep_both_nibbles() {
        // The high nibble comes from a logical shift (`lsr #4` folded
        // into the table load), so 0x80..0xff must not sign-extend.
        let fixture = Fixture::new(false);
        assert_eq!(format(&fixture, &[0xff, 0x80, 0x8a]), b"FF:80:8A\0".to_vec());
    }

    #[test]
    fn multiple_bytes_are_colon_separated_and_nul_terminated() {
        let fixture = Fixture::new(false);
        let result = unsafe { blob_to_hex([0x01u8, 0x23, 0xab].as_ptr(), 3) };
        assert!(!result.is_null());
        let heap = fixture.heap();
        assert_eq!(&heap[GUARD..GUARD + 9], b"01:23:AB\0", "the last ':' becomes the NUL");
    }

    #[test]
    fn allocates_one_byte_more_than_it_writes() {
        // 2n digits + (n-1) separators + the NUL is 3n bytes, but the
        // original asks for 3n+1: the last byte of every block it
        // returns is never written. Reproduced, not tightened.
        let fixture = Fixture::new(false);
        let blob = [0xdeu8, 0xad, 0xbe, 0xef];
        let written = format(&fixture, &blob);
        assert_eq!(written.len(), blob.len() * 3, "bytes actually written");
        assert_eq!(fixture.requests(), std::vec![(blob.len() as i32 * 3 + 1, 0, 0)]);
        let heap = fixture.heap();
        assert_eq!(heap[0], POISON, "nothing written before the block");
        assert!(
            heap[GUARD + written.len()..].iter().all(|&b| b == POISON),
            "nothing written past the terminator, including the block's spare byte",
        );
    }

    #[test]
    fn allocation_failure_records_the_diagnostic_triple_and_returns_null() {
        let fixture = Fixture::new(true);
        let blob = [0x11u8, 0x22];
        assert!(unsafe { blob_to_hex(blob.as_ptr(), blob.len() as i32) }.is_null());
        assert_eq!(fixture.requests(), std::vec![(7, 0, 0)]);
        assert_eq!(fixture.events(), std::vec![(0x22, 0x6f, 0x41, 0, 0)]);
    }

    #[test]
    fn negative_length_fails_in_the_allocator_and_takes_the_diagnostic_path() {
        // len*3 + 1 stays negative, so traced_alloc's own `size <= 0`
        // guard returns NULL before the underlying allocator is asked.
        let fixture = Fixture::new(false);
        let blob = [0x11u8; 4];
        for len in [-1i32, -2, -1000, i32::MIN] {
            assert!(unsafe { blob_to_hex(blob.as_ptr(), len) }.is_null(), "len = {len}");
        }
        assert!(fixture.requests().is_empty(), "the mock heap is never reached");
        assert_eq!(fixture.events().len(), 4, "one diagnostic per attempt");
        assert!(fixture.events().iter().all(|&e| e == (0x22, 0x6f, 0x41, 0, 0)));
    }

    #[test]
    fn negative_length_that_wraps_positive_underflows_the_block() {
        // Faithful hazard: len = -0x55555555 wraps len*3 + 1 back to 2,
        // the allocation succeeds, the `blt` loop never runs, and the
        // terminator store lands one byte *before* the block. The guard
        // byte catches it; no real caller can reach this.
        let fixture = Fixture::new(false);
        let blob = [0x11u8; 4];
        let len = -0x5555_5555i32;
        assert_eq!(len.wrapping_mul(3).wrapping_add(1), 2, "the wrap this test relies on");
        let result = unsafe { blob_to_hex(blob.as_ptr(), len) };
        assert!(!result.is_null(), "the allocation succeeds");
        let heap = fixture.heap();
        assert_eq!(heap[0], 0, "the terminator lands before the block");
        assert!(heap[GUARD..].iter().all(|&b| b == POISON), "the block itself is untouched");
    }

    #[test]
    fn matches_the_reference_across_lengths_and_contents() {
        let fixture = Fixture::new(false);
        // A cheap LCG so the contents span the whole byte range at every
        // length, without pulling in a dependency.
        let mut state: u32 = 0x1234_5678;
        for len in 1usize..=64 {
            let blob: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect();
            assert_eq!(format(&fixture, &blob), reference(&blob), "len = {len}");
            assert_eq!(
                fixture.requests().last().copied(),
                Some((len as i32 * 3 + 1, 0, 0)),
                "len = {len}",
            );
        }
    }

    #[test]
    fn the_digit_table_is_the_image_table() {
        assert_eq!(&HEX_DIGITS, b"0123456789ABCDEF");
        assert_eq!(HEX_DIGITS_ADDRESS + 0xaed8, 0x08a1_9cb4, "the image address of the table");
    }
}
