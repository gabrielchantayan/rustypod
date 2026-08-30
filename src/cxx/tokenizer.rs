//! `tokenizer_next` — original: `FUN_081613d8` @ 0x081613d8
//! (**120 bytes** of code, 0x081613d8..0x08161450; the extent is exact —
//! the body ends in `pop {r0, r1, r2, r3, r4, r5, r6, pc}` @ 0x0816144c
//! and the next function, a standalone 20-byte three-word copy used only
//! by a tail `b` from 0x081e8764, starts at 0x08161450 with
//! `ldm r1, {r2, r3}`. **41 `bl` call sites, 0 `b`, 0 predicated**,
//! binary-verified by decoding every B/BL word in `osos.dec`.)
//!
//! The "next token" step of retailOS's **UTF-16 string tokenizer**: it
//! pulls the next `{begin, end}` u16 range out of a cursor object, split on
//! a caller-chosen delimiter code unit, with optional double-quote regions
//! and backslash escapes, and a countdown after which the last token
//! absorbs the rest of the input. The caller at 0x081ba9ac shows the
//! idiom: build the cursor with the constructor @ 0x08161464
//! (`delim = ':'`, `remaining = 0x7fffffff`, `allow_quotes = 1`), then call
//! `tokenizer_next` repeatedly and feed each range to the UTF-16 number
//! parser @ 0x080f01c4 — an `HH:MM:SS` time-of-day split.
//!
//! ## The cursor object (21 bytes written by the constructors)
//!
//! Two constructors build it, both unported:
//!
//! - **0x08161464** (17 `bl` sites) — `(this, &range, delim, remaining,
//!   allow_quotes)`: copies the caller's `{begin, end}` pair into +0x00/
//!   +0x04 (`bl 0x081bb6a4`), stores `delim` at +0x08, seeds the cursor
//!   +0x0c with `range.begin` (`ldr r1, [r4]; str r1, [r0, #12]`), the
//!   countdown +0x10 and the quote flag byte +0x14.
//! - **0x08161494** (1 `bl` site) — the same but zeroes +0x00/+0x04 and
//!   the cursor (`bl 0x081bb6b8`), i.e. an already-exhausted tokenizer
//!   over an empty range.
//!
//! ```text
//! +0x00  u32  begin         — start of the whole UTF-16 input range
//! +0x04  u32  end           — one past the last input code unit
//! +0x08  u16  delimiter     — the code unit the scan stops on
//! +0x0a  u16  (pad, never accessed)
//! +0x0c  u32  cursor        — scan position; NULL or >= end = exhausted
//! +0x10  i32  remaining     — delimited scans left; at < 1 the next token
//!                             absorbs the rest of the input
//! +0x14  u8   allow_quotes  — nonzero makes '"' toggle a quoted region
//! ```
//!
//! ## Algorithm
//!
//! ```text
//! 081613d8  push {r0-r3, r4, r5, r6, lr}  @ spill slots double as locals
//! 081613dc  mov  r5, r0              @ r5 = out (sret slot for the pair)
//! 081613e0  add  r0, sp, #8
//! 081613e4  mov  r4, r1              @ r4 = state
//! 081613e8  bl   0x081bb6b8          @ zero the empty pair {0, 0}
//! 081613ec  ldr  r1, [r4, #12]       @ cursor
//! 081613f0  cmp  r1, #0
//! 081613f4  ldrne r2, [r4, #4]       @ end
//! 081613f8  cmpne r1, r2
//! 081613fc  addcs r1, sp, #8
//! 08161400  bcs  0x08161444          @ cursor NULL or >= end: empty token
//! 08161404  ldr  r0, [r4, #16]       @ remaining
//! 08161408  cmp  r0, #1
//! 0816140c  movlt r0, r2             @ countdown spent: token runs to end
//! 08161410  blt  0x0816142c
//! 08161414  ldrh r3, [r4, #8]        @ delimiter
//! 08161418  mov  r0, r4
//! 0816141c  bl   0x08161364          @ scan_token_end(state, cursor, end)
//! 08161420  ldr  r1, [r4, #16]
//! 08161424  sub  r1, r1, #1
//! 08161428  str  r1, [r4, #16]       @ remaining--  (scan path only)
//! 0816142c  ldr  r1, [r4, #12]       @ cursor (reloaded)
//! 08161430  str  r0, [sp, #4]        @ pair = {cursor, stop}
//! 08161434  str  r1, [sp]
//! 08161438  add  r0, r0, #2
//! 0816143c  mov  r1, sp
//! 08161440  str  r0, [r4, #12]       @ cursor = stop + 2 (past delimiter)
//! 08161444  mov  r0, r5
//! 08161448  bl   0x081bb6a4          @ *out = pair (two word stores)
//! 0816144c  pop  {r0-r3, r4, r5, r6, pc}  @ r0 restored to `out`
//! ```
//!
//! The scan helper @ 0x08161364 (76 bytes; its ONLY call site in the image
//! is 0x0816141c above — binary-verified) walks u16 code units from
//! `cursor` until `end`, and stops at the first `delimiter` that is neither
//! inside a quoted region nor backslash-escaped:
//!
//! ```text
//! quoted = escaped = false
//! while p != end:
//!     c = *p
//!     if quoted:                       quoted = (c != '"')  — note: NO
//!         advance                                   escape handling in
//!     elif allow_quotes && c == '"':   quoted = true        quotes
//!     elif !escaped:
//!         if c == '\\': escaped = true
//!         elif c == delimiter: return p
//!     else: escaped = false            @ one char after '\' is literal
//!     advance
//! return p                             @ == end when nothing matched
//! ```
//!
//! Inside quotes a backslash is NOT special (only `"` toggles the region),
//! and the `allow_quotes` byte is re-read from the object on every
//! non-quoted character. When the countdown (`remaining`, a signed word
//! compared with `movlt`/`blt` against 1) is spent, no scan happens: the
//! token is `{cursor, end}` and the cursor advances to `end + 2`, so the
//! next call reports exhaustion. `remaining` is decremented ONLY on the
//! scan path. A tokenizer built with `remaining = 0` therefore returns the
//! whole rest of the input as a single token.
//!
//! The result is returned the ADS small-struct way: the caller passes an
//! 8-byte slot in r0, the function writes the pair through it, and the
//! `pop {r0, ...}` epilogue restores r0 to that same slot pointer, which
//! the port mirrors by returning `out`.
//!
//! # Deviations
//!
//! - The two shared 8-byte helpers are inlined, matching established
//!   precedent: the empty-pair zero @ 0x081bb6b8 (`mov r1, #0; str r1,
//!   [r0]; str r1, [r0, #4]`) and the pair copy @ 0x081bb6a4 (two word
//!   loads/stores, decoded from its own bytes) become two word stores
//!   each.
//! - The scan helper @ 0x08161364 is ported as the private
//!   [`scan_token_end`] — it has no other call site, so no dispatch seam
//!   is warranted.
//! - Struct-pointer fields are modeled as `u32` firmware addresses in a
//!   `#[repr(C)]` object (see [`Tokenizer`]); on host, tests map the
//!   fixture below 4 GiB so the words round-trip. No literal byte offsets
//!   appear in the code.

/// The tokenizer cursor object; see the module header for how the
/// constructors @ 0x08161464 / 0x08161494 fill it.
#[repr(C)]
pub struct Tokenizer {
    /// +0x00: start of the whole UTF-16 input range (a `u16 *`).
    pub begin: u32,
    /// +0x04: one past the last input code unit (a `u16 *`).
    pub end: u32,
    /// +0x08: the code unit the scan stops on.
    pub delimiter: u16,
    /// +0x0a: never read or written by any member.
    pub pad_0a: u16,
    /// +0x0c: the scan cursor (a `u16 *`); NULL or `>= end` when exhausted.
    pub cursor: u32,
    /// +0x10: delimited scans left, signed; below 1 the next token absorbs
    /// the rest of the input. Decremented on the scan path only.
    pub remaining: i32,
    /// +0x14: nonzero makes `'"'` toggle a quoted region during the scan.
    pub allow_quotes: u8,
    // +0x15..+0x17: tail padding; the constructors write exactly 21 bytes
    // and callers reserve 24 (the `auStack_3c [24]` of 0x081ba9ac).
}

/// Target byte size of [`Tokenizer`], padding included.
pub const TOKENIZER_SIZE: usize = 0x18;

const _: [u8; 0x00] = [0; core::mem::offset_of!(Tokenizer, begin)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(Tokenizer, end)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(Tokenizer, delimiter)];
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Tokenizer, cursor)];
const _: [u8; 0x10] = [0; core::mem::offset_of!(Tokenizer, remaining)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(Tokenizer, allow_quotes)];
const _: [u8; TOKENIZER_SIZE] = [0; core::mem::size_of::<Tokenizer>()];

/// The code units with syntactic meaning to the scan.
const DOUBLE_QUOTE: u16 = 0x22; // '"'
const BACKSLASH: u16 = 0x5c; // '\\'

/// scan_token_end — original: `FUN_08161364` @ 0x08161364 (76 bytes;
/// exactly one call site, the `bl` @ 0x0816141c inside `tokenizer_next`,
/// binary-scanned).
///
/// Returns the position of the first `delimiter` code unit in
/// `[cursor, end)` that is neither quoted nor backslash-escaped, or `end`
/// when there is none. Inside a quoted region only `'"'` is special — a
/// backslash does NOT escape there. The `allow_quotes` byte is re-read
/// from `state` for every non-quoted character, matching the original's
/// in-loop `ldrb r5, [r0, #20]`.
///
/// # Safety
///
/// `[cursor, end)` must be a readable u16 range; the original stops on
/// pointer equality with `end`, so a cursor past `end` would walk off the
/// end of the buffer — the port inherits that contract.
unsafe fn scan_token_end(state: &Tokenizer, mut p: *const u16, end: *const u16) -> *const u16 {
    let delimiter = state.delimiter;
    let mut escaped = false;
    let mut quoted = false;
    while p != end {
        let unit = p.read();
        if quoted {
            if unit == DOUBLE_QUOTE {
                quoted = false;
            }
        } else if state.allow_quotes != 0 && unit == DOUBLE_QUOTE {
            quoted = true;
        } else if !escaped {
            if unit == BACKSLASH {
                escaped = true;
            } else if unit == delimiter {
                return p;
            }
        } else {
            escaped = false;
        }
        p = p.add(1);
    }
    p
}

/// tokenizer_next — original: `FUN_081613d8` @ 0x081613d8
/// (120 bytes; 41 `bl` call sites, 0 `b`, 0 predicated, binary-scanned).
///
/// Writes the next token's `{begin, end}` u16 range to `out` and advances
/// the cursor past the delimiter. When the tokenizer is exhausted
/// (`cursor == NULL` or `cursor >= end`) the token is `{0, 0}` and the
/// object is left untouched. When the scan countdown is spent
/// (`remaining < 1`, signed) the token runs to `end` unquoted/unescaped
/// and the cursor lands at `end + 2`. Returns `out`, as the original's
/// `pop {r0, ...}` epilogue does.
///
/// # Safety
///
/// `out` must point at two writable words and `state` at a live
/// [`Tokenizer`]. On the scan path `[cursor, end)` must be a readable u16
/// range (see [`scan_token_end`]).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tokenizer_next(out: *mut u32, state: *mut Tokenizer) -> *mut u32 {
    let state = &mut *state;
    let cursor = state.cursor;
    if cursor != 0 && cursor < state.end {
        let stop = if state.remaining >= 1 {
            let found =
                scan_token_end(state, cursor as *const u16, state.end as *const u16) as u32;
            state.remaining -= 1;
            found
        } else {
            state.end
        };
        state.cursor = stop.wrapping_add(2);
        out.write(cursor);
        out.add(1).write(stop);
    } else {
        out.write(0);
        out.add(1).write(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::sync::{LazyLock, Mutex};
    use std::vec::Vec;

    /// The shared slab fixture is global, so the tests serialize on one
    /// lock and re-init their fixture in place.
    static TOKENIZER_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Byte offset of the [`Tokenizer`] object inside the slab; the u16
    /// text lives at the slab base.
    const STATE_OFFSET: usize = 0x1000;

    /// Maps the fixture slab once per process. The port widens `u32`
    /// cursor words into host pointers and dereferences them, so the text
    /// and the object must live below 4 GiB; `None` means this host cannot
    /// supply such a mapping and the tests skip rather than crash. The
    /// mapper never unmaps, so a second `try_map_u32_slab` with the same
    /// hint would land above 4 GiB and skip silently — hence the
    /// process-wide `LazyLock`.
    fn try_slab() -> Option<*mut u8> {
        static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
            crate::testing::try_map_u32_slab(crate::testing::hints::TOKENIZER, 0x2000)
                .map(|p| p as usize)
        });
        SLAB.map(|p| p as *mut u8)
    }

    /// A fixture: `text` as u16 code units at the slab base, with the
    /// tokenizer object at `STATE_OFFSET` pointing at it.
    struct Fixture {
        base: *mut u8,
        state: *mut Tokenizer,
    }

    impl Fixture {
        /// Initializes a tokenizer over `text` in the shared slab.
        fn new(text: &[u16], delimiter: u16, remaining: i32, allow_quotes: u8) -> Option<Self> {
            let slab = try_slab()?;
            unsafe {
                let words = slab as *mut u16;
                for (i, &unit) in text.iter().enumerate() {
                    words.add(i).write(unit);
                }
                let state = slab.add(STATE_OFFSET) as *mut Tokenizer;
                (*state).begin = slab as u32;
                (*state).end = (slab as usize + text.len() * 2) as u32;
                (*state).delimiter = delimiter;
                (*state).cursor = slab as u32;
                (*state).remaining = remaining;
                (*state).allow_quotes = allow_quotes;
                Some(Fixture { base: slab, state })
            }
        }

        /// Calls the port and returns the token as code-unit indices into
        /// the text (or `None` for the NULL `{0, 0}` empty token), plus the
        /// returned pointer.
        fn next(&mut self) -> (Option<(usize, usize)>, *mut u32) {
            unsafe {
                let mut out = [0xdead_beefu32; 2];
                let ret = tokenizer_next(out.as_mut_ptr(), self.state);
                let token = if out == [0, 0] {
                    None
                } else {
                    let base = self.base as usize;
                    Some(((out[0] as usize - base) / 2, (out[1] as usize - base) / 2))
                };
                (token, ret)
            }
        }

        fn cursor_index(&self) -> usize {
            unsafe { (((*self.state).cursor as usize) - self.base as usize) / 2 }
        }

        fn remaining(&self) -> i32 {
            unsafe { (*self.state).remaining }
        }
    }

    /// Runs `body` with a fresh fixture, or records the skip when this host
    /// cannot map below 4 GiB.
    fn with_fixture<T>(
        text: &[u16],
        delimiter: u16,
        remaining: i32,
        allow_quotes: u8,
        body: impl FnOnce(&mut Fixture) -> T,
    ) -> Option<T> {
        let _lock = TOKENIZER_TEST_LOCK.lock().unwrap();
        let mut fixture = Fixture::new(text, delimiter, remaining, allow_quotes)?;
        Some(body(&mut fixture))
    }

    fn skip() -> bool {
        crate::testing::note_missing_u32_fixture("cxx/tokenizer")
    }

    /// Encodes ASCII test strings as u16 code units.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn null_cursor_yields_empty_token_and_untouched_state() {
        let Some(()) = with_fixture(&wide("a:b"), b':' as u16, 7, 0, |f| {
            unsafe {
                (*f.state).cursor = 0;
            }
            let (token, _) = f.next();
            assert_eq!(token, None);
            assert_eq!(f.remaining(), 7, "no scan, no decrement");
            assert_eq!(unsafe { (*f.state).cursor }, 0);
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn cursor_at_end_yields_empty_token() {
        let Some(()) = with_fixture(&wide("ab"), b':' as u16, 7, 0, |f| {
            unsafe {
                (*f.state).cursor = (*f.state).end;
                let (token, _) = f.next();
                assert_eq!(token, None);
                // Cursor past the end is equally exhausted (unsigned >=).
                (*f.state).cursor = (*f.state).end + 2;
                let (token, _) = f.next();
                assert_eq!(token, None);
                assert_eq!(f.remaining(), 7);
            }
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn splits_on_delimiter_and_exhausts() {
        // The 0x081ba9ac idiom: HH:MM:SS with ':' and a huge countdown.
        let Some(()) = with_fixture(&wide("12:34:56"), b':' as u16, 0x7fff_ffff, 1, |f| {
            assert_eq!(f.next().0, Some((0, 2)), "12");
            assert_eq!(f.cursor_index(), 3, "cursor advanced past ':'");
            assert_eq!(f.remaining(), 0x7fff_fffe);
            assert_eq!(f.next().0, Some((3, 5)), "34");
            assert_eq!(f.next().0, Some((6, 8)), "56 runs to end");
            assert_eq!(f.remaining(), 0x7fff_fffc, "the end-run still scanned");
            assert_eq!(f.next().0, None, "cursor = end + 2 is exhausted");
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn spent_countdown_makes_last_token_absorb_the_rest() {
        // remaining = 2: two delimited scans, then the rest unsplit.
        let Some(()) = with_fixture(&wide("a:b:c:d"), b':' as u16, 2, 0, |f| {
            assert_eq!(f.next().0, Some((0, 1)), "a");
            assert_eq!(f.next().0, Some((2, 3)), "b");
            assert_eq!(f.remaining(), 0);
            // remaining < 1: no scan, the delimiters stay in the token.
            assert_eq!(f.next().0, Some((4, 7)), "c:d verbatim");
            assert_eq!(f.remaining(), 0, "the absorb path never decrements");
            assert_eq!(f.next().0, None);
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn zero_countdown_returns_the_whole_input_as_one_token() {
        let Some(()) = with_fixture(&wide("x:y:z"), b':' as u16, 0, 0, |f| {
            assert_eq!(f.next().0, Some((0, 5)));
            assert_eq!(f.next().0, None);
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn quoted_delimiter_is_not_a_split_when_quotes_enabled() {
        let Some(()) = with_fixture(&wide("\"a:b\":c"), b':' as u16, 9, 1, |f| {
            assert_eq!(f.next().0, Some((0, 5)), "\"a:b\" including the quotes");
            assert_eq!(f.next().0, Some((6, 7)), "c");
            assert_eq!(f.next().0, None);
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn quotes_are_ordinary_chars_when_quotes_disabled() {
        let Some(()) = with_fixture(&wide("\"a:b\":c"), b':' as u16, 9, 0, |f| {
            assert_eq!(f.next().0, Some((0, 2)), "\"a");
            assert_eq!(f.next().0, Some((3, 5)), "b\"");
            assert_eq!(f.next().0, Some((6, 7)), "c");
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn escaped_delimiter_is_not_a_split() {
        let Some(()) = with_fixture(&wide("a\\:b:c"), b':' as u16, 9, 0, |f| {
            assert_eq!(f.next().0, Some((0, 4)), "a\\:b — '\\:' is literal");
            assert_eq!(f.next().0, Some((5, 6)), "c");
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn double_backslash_does_not_escape_the_delimiter() {
        // "a\\:b" — the second backslash is the escaped char, so ':' splits.
        let Some(()) = with_fixture(&wide("a\\\\:b"), b':' as u16, 9, 0, |f| {
            assert_eq!(f.next().0, Some((0, 3)), "a\\\\");
            assert_eq!(f.next().0, Some((4, 5)), "b");
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn backslash_is_not_an_escape_inside_quotes() {
        // "\"a\"b:c" with quotes on: the backslash at index 2 is inert
        // inside the quoted region, so the '"' at index 3 CLOSES it and
        // the ':' at index 5 is an ordinary split point. Contrast with an
        // escaped quote outside quotes, which would not open one at all.
        let Some(()) = with_fixture(&wide("\"a\\\"b:c"), b':' as u16, 9, 1, |f| {
            assert_eq!(f.next().0, Some((0, 5)), "\"a\\\"b — the quote closed");
            assert_eq!(f.next().0, Some((6, 7)), "c");
            assert_eq!(f.next().0, None);
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn unterminated_quote_runs_to_end() {
        let Some(()) = with_fixture(&wide("\"a:b"), b':' as u16, 9, 1, |f| {
            assert_eq!(f.next().0, Some((0, 4)), "no closing quote, no split");
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn trailing_delimiter_exhausts_immediately() {
        // "a:": the first scan stops at the trailing ':' and the cursor
        // lands ON end (stop + 2), so the exhaustion guard fires on the
        // next call — a zero-width tail token is never produced.
        let Some(()) = with_fixture(&wide("a:"), b':' as u16, 9, 0, |f| {
            assert_eq!(f.next().0, Some((0, 1)), "a");
            assert_eq!(f.cursor_index(), 2, "cursor sits exactly on end");
            assert_eq!(f.next().0, None);
        }) else {
            assert!(skip());
            return;
        };
    }

    #[test]
    fn returns_the_out_pointer() {
        let Some(()) = with_fixture(&wide("a:b"), b':' as u16, 9, 0, |f| {
            let mut out = [0u32; 2];
            let ret = unsafe { tokenizer_next(out.as_mut_ptr(), f.state) };
            assert_eq!(ret, out.as_mut_ptr(), "the epilogue restores r0 to out");
        }) else {
            assert!(skip());
            return;
        };
    }
}
