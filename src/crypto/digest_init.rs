//! Apple's proprietary message-digest context init (MBA-obfuscated
//! FairPlay/DRM crypto cluster, distinct from the vendored OpenSSL copy).
//!
//! `digest_init` — original: `FUN_082f0a1c` @ 0x082f0a1c (136 bytes:
//! 116 of code plus the five literal-pool words @ 0x082f0a90..0x082f0aa4
//! — Ghidra's `functions.csv` reports 116 and drops the pool; the next
//! function starts at 0x082f0aa4. 23 `bl` call sites, zero predicated
//! forms and zero plain `b`, binary-scanned over every branch word in
//! `work/firmware/osos.dec`).
//!
//! # What it is
//!
//! The init half of a two-algorithm digest used by the obfuscated HMAC
//! machinery in 0x082f0xxx..0x0835xxxx:
//!
//! - `digest_update` @ 0x08338384 takes `(data, ctx, len)`.
//! - `digest_final` @ 0x082fbbfc takes `(out, ctx)`, dispatches on
//!   `ctx->algorithm & 0xff == 2` and separately tests flag bit `0x100`
//!   of the stored algorithm word — which is why init masks with
//!   `0x1ff` (eight kind bits plus that flag) rather than `0xff`.
//! - The HMAC key schedule @ 0x0835ab54 is textbook HMAC over a 64-byte
//!   block: pads the key, XORs with 0x36 (ipad) / 0x5c (opad) — each
//!   hidden behind the MBA identity `(x * -0x4b + 0x24) * -99 - 0x14`
//!   (≡ x mod 256) — then calls init/update/final.
//!
//! `algorithm & 0xff` selects the digest: 1 = 16-byte state (MD5 family),
//! 2 = 20-byte state (SHA-1 family). Both IV sets are NON-standard —
//! 0xfcd4a0ff / 0x7dbc3877 / 0x14dd9b02 / 0x93f6038a (plus 0xc658de10
//! for the 20-byte variant) match neither MD5/SHA-1 nor any byte swap of
//! them; the words appear nowhere else in the image. Any other kind
//! leaves the state words alone and returns 0 with only the counter,
//! length and algorithm fields written.
//!
//! # Context layout (pinned by init + callers)
//!
//! ```text
//! +0x40  u32  message-length counter, low   (zeroed)
//! +0x44  u32  message-length counter, high  (zeroed)
//! +0x48  u32[5]  digest state words (4 used for kind 1, 5 for kind 2)
//! +0x60  u32  state length in bytes: 0, then 16 or 20
//! +0x64  u32  algorithm selector, `algorithm & 0x1ff`
//! +0x68  ...  64-byte message-block buffer (never touched here; the
//!              HMAC caller @ 0x0834f42c feeds ctx+0x68 to update)
//! ```
//!
//! `digest_final`'s sibling wrapper @ 0x0834f42c re-initializes a used
//! context with `digest_init(ctx, ctx->algorithm)` — the stored word at
//! +0x64 round-trips as the selector, confirming the mask.
//!
//! # Body
//!
//! ```text
//! 082f0a1c:  lsl  r2,r1,#0x17
//! 082f0a20:  lsr  r2,r2,#0x17      ; r2 = algorithm & 0x1ff
//! 082f0a24:  str  r2,[r0,#0x64]   ; ctx->algorithm
//! 082f0a28:  mov  r2,#0
//! 082f0a2c:  str  r2,[r0,#0x44]   ; length_hi = 0
//! 082f0a30:  and  r1,r1,#0xff
//! 082f0a34:  str  r2,[r0,#0x40]   ; length_lo = 0
//! 082f0a38:  cmp  r1,#1
//! 082f0a3c:  str  r2,[r0,#0x60]   ; state_len = 0
//! 082f0a40:  beq  0x082f0a5c      ; kind 1: skip the 5th word
//! 082f0a44:  cmp  r1,#2
//! 082f0a48:  bne  0x082f0a88      ; other kinds: return 0 now
//! 082f0a4c:  ldr  r1,=0xc658de10
//! 082f0a50:  str  r1,[r0,#0x58]   ; state[4]
//! 082f0a54:  mov  r1,#4
//! 082f0a58:  str  r1,[r0,#0x60]   ; state_len = 4
//! 082f0a5c:  ldr  r1,=0xfcd4a0ff  ; common: state[0..4]
//! 082f0a60:  str  r1,[r0,#0x48]
//! 082f0a64:  ldr  r1,=0x7dbc3877
//! 082f0a68:  str  r1,[r0,#0x4c]
//! 082f0a6c:  ldr  r1,=0x14dd9b02
//! 082f0a70:  str  r1,[r0,#0x50]
//! 082f0a74:  ldr  r1,=0x93f6038a
//! 082f0a78:  str  r1,[r0,#0x54]
//! 082f0a7c:  ldr  r1,[r0,#0x60]
//! 082f0a80:  add  r1,r1,#0x10     ; state_len += 16
//! 082f0a84:  str  r1,[r0,#0x60]
//! 082f0a88:  mov  r0,#0
//! 082f0a8c:  bx   lr              ; always returns 0
//! ```
//!
//! Deviations: none semantic. The store order above differs from the
//! original's interleaved scheduling (LLVM reorders anyway); the
//! observable result — which words are written, with what, per kind —
//! is identical.
///
/// Digest kind 1: 16-byte state (MD5 family, custom IVs).
pub const DIGEST_KIND_16: u32 = 1;
/// Digest kind 2: 20-byte state (SHA-1 family, custom IVs).
pub const DIGEST_KIND_20: u32 = 2;

/// First state word of the 20-byte variant, stored at +0x58 before the
/// common four overwrite +0x48..+0x54.
const STATE4_IV: u32 = 0xc658de10;
/// Common four state words @ +0x48..+0x54 for both kinds.
const STATE_IVS: [u32; 4] = [0xfcd4a0ff, 0x7dbc3877, 0x14dd9b02, 0x93f6038a];

/// Digest context as far as `digest_init` pins it. The block buffer at
/// +0x68 belongs to update/final and is not part of this struct.
#[repr(C)]
pub struct DigestCtx {
    /// +0x00..+0x40: never touched by init (caller-owned head, e.g. the
    /// HMAC wrapper's own bookkeeping).
    pub reserved_00: [u32; 16],
    /// +0x40: message-length counter, low word.
    pub length_lo: u32,
    /// +0x44: message-length counter, high word.
    pub length_hi: u32,
    /// +0x48: digest state, 4 words (kind 1) or 5 words (kind 2).
    pub state: [u32; 5],
    /// +0x5c: unused by init; kept so `state_len` lands at +0x60.
    pub reserved_5c: u32,
    /// +0x60: number of initialized state bytes (0, 16 or 20).
    pub state_len: u32,
    /// +0x64: algorithm selector, stored as `algorithm & 0x1ff`
    /// (low byte = kind, bit 8 = flag read by `digest_final`).
    pub algorithm: u32,
}

/// Initialize a digest context. Always returns 0; unknown kinds still
/// zero the counter/length fields and store the masked selector.
///
/// # Safety
/// `ctx` must point to at least 0x68 writable bytes, as the original
/// requires of its callers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn digest_init(ctx: *mut DigestCtx, algorithm: u32) -> u32 {
    let ctx = &mut *ctx;
    ctx.algorithm = algorithm & 0x1ff;
    ctx.length_hi = 0;
    ctx.length_lo = 0;
    ctx.state_len = 0;
    match algorithm & 0xff {
        kind if kind == DIGEST_KIND_16 => {}
        kind if kind == DIGEST_KIND_20 => {
            ctx.state[4] = STATE4_IV;
            ctx.state_len = 4;
        }
        _ => return 0,
    }
    ctx.state[0] = STATE_IVS[0];
    ctx.state[1] = STATE_IVS[1];
    ctx.state[2] = STATE_IVS[2];
    ctx.state[3] = STATE_IVS[3];
    ctx.state_len += 16;
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{digest_init, DigestCtx, DIGEST_KIND_16, DIGEST_KIND_20};

    /// A sentinel no write may ever leave in place.
    const SENTINEL: u32 = 0xdead_beef;

    /// Context bracketed by guard words; every field starts dirtied so a
    /// store the original never makes shows up as a flipped sentinel.
    struct Fixture {
        before: [u32; 4],
        ctx: DigestCtx,
        after: [u32; 4],
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                before: [SENTINEL; 4],
                ctx: DigestCtx {
                    reserved_00: [SENTINEL; 16],
                    length_lo: SENTINEL,
                    length_hi: SENTINEL,
                    state: [SENTINEL; 5],
                    reserved_5c: SENTINEL,
                    state_len: SENTINEL,
                    algorithm: SENTINEL,
                },
                after: [SENTINEL; 4],
            }
        }

        fn init(&mut self, algorithm: u32) -> u32 {
            unsafe { digest_init(&mut self.ctx, algorithm) }
        }

        fn assert_untouched(&self) {
            assert_eq!(self.before, [SENTINEL; 4], "write before the context");
            assert_eq!(self.after, [SENTINEL; 4], "write past the context");
            assert_eq!(
                self.ctx.reserved_00,
                [SENTINEL; 16],
                "init must not touch +0x00..+0x40"
            );
            assert_eq!(self.ctx.reserved_5c, SENTINEL, "init must not touch +0x5c");
        }

        fn assert_common_writes(&self, algorithm: u32) {
            assert_eq!(self.ctx.algorithm, algorithm & 0x1ff);
            assert_eq!(self.ctx.length_lo, 0);
            assert_eq!(self.ctx.length_hi, 0);
        }
    }

    #[test]
    fn kind_16_inits_four_state_words_and_len_16() {
        let mut f = Fixture::new();
        assert_eq!(f.init(DIGEST_KIND_16), 0);
        f.assert_untouched();
        f.assert_common_writes(DIGEST_KIND_16);
        assert_eq!(f.ctx.state[0], 0xfcd4a0ff);
        assert_eq!(f.ctx.state[1], 0x7dbc3877);
        assert_eq!(f.ctx.state[2], 0x14dd9b02);
        assert_eq!(f.ctx.state[3], 0x93f6038a);
        assert_eq!(
            f.ctx.state[4], SENTINEL,
            "kind 1 must not write the 5th state word"
        );
        assert_eq!(f.ctx.state_len, 16);
    }

    #[test]
    fn kind_20_inits_five_state_words_and_len_20() {
        let mut f = Fixture::new();
        assert_eq!(f.init(DIGEST_KIND_20), 0);
        f.assert_untouched();
        f.assert_common_writes(DIGEST_KIND_20);
        assert_eq!(
            f.ctx.state,
            [0xfcd4a0ff, 0x7dbc3877, 0x14dd9b02, 0x93f6038a, 0xc658de10]
        );
        assert_eq!(f.ctx.state_len, 20);
    }

    #[test]
    fn unknown_kinds_only_write_counters_and_selector() {
        for kind in [0u32, 3, 0xfe, 0xff] {
            let mut f = Fixture::new();
            assert_eq!(f.init(kind), 0, "every kind returns 0");
            f.assert_untouched();
            f.assert_common_writes(kind);
            assert_eq!(f.ctx.state_len, 0);
            assert_eq!(
                f.ctx.state,
                [SENTINEL; 5],
                "kind {kind:#x} must not touch the state words"
            );
        }
    }

    #[test]
    fn dispatch_uses_low_byte_but_stores_nine_bits() {
        // 0x102: kind 2 with the 0x100 flag digest_final reads.
        let mut f = Fixture::new();
        assert_eq!(f.init(0x102), 0);
        f.assert_untouched();
        assert_eq!(f.ctx.algorithm, 0x102);
        assert_eq!(f.ctx.state_len, 20);
        assert_eq!(f.ctx.state[4], 0xc658de10);
    }

    #[test]
    fn bit_nine_and_above_are_masked_off_the_stored_selector() {
        // 0x202: kind 2, flag 0x200 — the store keeps 0x1ff only, so the
        // flag is dropped while the low byte still dispatches.
        let mut f = Fixture::new();
        assert_eq!(f.init(0x202), 0);
        f.assert_untouched();
        assert_eq!(f.ctx.algorithm, 0x002);
        assert_eq!(f.ctx.state_len, 20);

        // 0xffff_fe01: low byte kind 1, high bits all set.
        let mut f = Fixture::new();
        assert_eq!(f.init(0xffff_fe01), 0);
        f.assert_untouched();
        assert_eq!(f.ctx.algorithm, 0x001);
        assert_eq!(f.ctx.state_len, 16);
    }

    #[test]
    fn reinit_with_stored_selector_round_trips() {
        // The wrapper @ 0x0834f42c re-inits with ctx->algorithm; a dirty
        // context must come back fully pristine.
        let mut f = Fixture::new();
        f.init(DIGEST_KIND_20);
        f.ctx.length_lo = 0x1111_1111;
        f.ctx.length_hi = 0x2222_2222;
        f.ctx.state_len = 0x3333_3333;
        let stored = f.ctx.algorithm;
        assert_eq!(f.init(stored), 0);
        f.assert_untouched();
        assert_eq!(f.ctx.algorithm, stored);
        assert_eq!(f.ctx.length_lo, 0);
        assert_eq!(f.ctx.length_hi, 0);
        assert_eq!(f.ctx.state_len, 20);
        assert_eq!(
            f.ctx.state,
            [0xfcd4a0ff, 0x7dbc3877, 0x14dd9b02, 0x93f6038a, 0xc658de10]
        );
    }
}
