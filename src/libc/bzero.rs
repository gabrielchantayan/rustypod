//! bzero — original: `FUN_0805cfb4` @ 0x0805cfb4 (76 bytes; 55 call
//! sites, binary-scanned b/bl words).
//!
//! A third zero-fill in the image, independent of the ADS runtime pair in
//! libc/memzero.rs (0x0800027c/0x080002d4): signed length, defensive
//! `len < 0` early-out, and its own alignment strategy. Algorithm:
//!
//! - `len < 0`: return (the ADS pair has no such guard).
//! - `len > 0x10`: byte-fill until `dst` is 4-byte aligned (the
//!   length bound guarantees the alignment prologue cannot exhaust the
//!   buffer), then word-fill while `len >= 4`.
//! - byte-fill the remainder (`subs`/`bpl` — exactly `len` bytes total).
//!
//! Lengths of 16 or fewer skip straight to the byte loop, alignment be
//! damned. Pure memory writes — no hardware; host tests prove full
//! behavior against a reference fill.
//!
//! Deviation: none in behavior. Writes go through `write_volatile` so
//! LLVM's loop-idiom pass cannot rewrite the loops into a `memset` libcall
//! (see PORTING.md gotchas).

/// bzero — original: `FUN_0805cfb4` @ 0x0805cfb4 (76 bytes).
///
/// Zero-fills `len` bytes at `dst`. Negative `len` writes nothing.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn bzero(dst: *mut u8, len: i32) {
    if len < 0 {
        return;
    }
    let mut p = dst;
    let mut n = len;
    if n > 0x10 {
        while p as usize & 3 != 0 {
            n -= 1;
            p.write_volatile(0);
            p = p.add(1);
        }
        while n >= 4 {
            n -= 4;
            (p as *mut u32).write_volatile(0);
            p = p.add(4);
        }
    }
    while n > 0 {
        n -= 1;
        p.write_volatile(0);
        p = p.add(1);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;

    /// Fills a canary-patterned buffer, zeroes `len` at `offset`, and
    /// checks exactly that window (and nothing else) was cleared.
    fn check(offset: usize, len: i32) {
        let total = offset + len.max(0) as usize + 8;
        let mut buf = vec![0xa5u8; total];
        unsafe { bzero(buf.as_mut_ptr().add(offset), len) };
        for (i, &b) in buf.iter().enumerate() {
            let inside = i >= offset && i < offset + len.max(0) as usize;
            assert_eq!(
                b,
                if inside { 0 } else { 0xa5 },
                "byte {i} (offset {offset}, len {len})"
            );
        }
    }

    #[test]
    fn zeroes_every_alignment_and_short_length() {
        for offset in 0..4 {
            for len in 0..=20 {
                check(offset, len);
            }
        }
    }

    #[test]
    fn zeroes_long_lengths_across_the_word_loop() {
        for offset in 0..4 {
            for len in [17, 31, 32, 33, 63, 64, 65, 100] {
                check(offset, len);
            }
        }
    }

    #[test]
    fn negative_length_writes_nothing() {
        for len in [-1, -16, i32::MIN] {
            check(3, len);
        }
    }

    #[test]
    fn zero_length_writes_nothing() {
        check(0, 0);
        check(1, 0);
    }
}
