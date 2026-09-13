//! `search_query_token_score` — original: `FUN_08131734` @ `0x08131734`.
//!
//! Raw ARM occupies 168 bytes at `0x08131734..0x081317dc`: 164 bytes of code
//! followed by the `10000` literal at `0x081317d8`; the separately linked next
//! function begins at `0x081317dc`. It splits a NUL-terminated UTF-16 query on
//! U+0020, scores each nonempty token against a candidate through
//! `FUN_0813305c`, returns zero as soon as a token does not match, and otherwise
//! sums the token scores. A first-token score of 1000 is promoted to 10000.
//!
//! **7 direct `bl` call sites, all unconditional and no predicated `bl`**,
//! verified by decoding every ARM B/BL word in `work/firmware/osos.dec`:
//! `0x08131950`, `0x08131a74`, `0x08131b94`, `0x08131cbc`, `0x08132884`,
//! `0x0813299c`, and `0x08132ae8`.
//!
//! Deliberate deviation: the one direct callee, `FUN_0813305c` at `0x0813305c`,
//! is not yet ported. Target builds call its verified retailOS address; host
//! tests use a volatile scoring seam. The recovered fourth Ghidra argument is
//! dead: raw ARM overwrites r3 with the token length before the only call.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_TOKEN_MATCH_SCORE: usize = 0x0813_305c;
const FIRST_TOKEN_EXACT_SCORE: u32 = 1000;
const FIRST_TOKEN_EXACT_BONUS: u32 = 10000;

/// Scores one UTF-16 query token against a candidate.
pub type TokenMatchScore = unsafe extern "C" fn(
    context: *mut u8,
    candidate: *mut u8,
    token: *const u16,
    token_len: u32,
) -> u32;

/// Host seam for the unported token scorer.
#[derive(Clone, Copy)]
pub struct SearchQueryTokenScoreOps {
    pub score_token: TokenMatchScore,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_token_match_score(
    context: *mut u8,
    candidate: *mut u8,
    token: *const u16,
    token_len: u32,
) -> u32 {
    let score: TokenMatchScore = core::mem::transmute(RETAIL_TOKEN_MATCH_SCORE);
    score(context, candidate, token, token_len)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_token_match_score(
    _context: *mut u8,
    _candidate: *mut u8,
    _token: *const u16,
    _token_len: u32,
) -> u32 {
    panic!("install token-score host operations before scoring a query")
}

/// Host default before a test installs the retail scorer equivalent.
#[cfg(not(target_os = "none"))]
pub const DEFAULT_SEARCH_QUERY_TOKEN_SCORE_OPS: SearchQueryTokenScoreOps =
    SearchQueryTokenScoreOps { score_token: missing_token_match_score };

/// Host-side scorer seam. Target builds always call `0x0813305c`.
#[cfg(not(target_os = "none"))]
pub static mut SEARCH_QUERY_TOKEN_SCORE_OPS: SearchQueryTokenScoreOps =
    DEFAULT_SEARCH_QUERY_TOKEN_SCORE_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_token_match_score(
    context: *mut u8,
    candidate: *mut u8,
    token: *const u16,
    token_len: u32,
) -> u32 {
    let score = core::ptr::read_volatile(addr_of!(SEARCH_QUERY_TOKEN_SCORE_OPS.score_token));
    score(context, candidate, token, token_len)
}

/// Scores every space-separated UTF-16 token in `query` against `candidate`.
///
/// # Safety
///
/// `query` must point to an aligned, NUL-terminated UTF-16 sequence. `context`
/// and `candidate` must satisfy the token scorer's contract. Like retailOS,
/// this function does not NULL-check any of those pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(all(not(test), not(target_os = "none")), no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn search_query_token_score(
    context: *mut u8,
    candidate: *mut u8,
    query: *const u16,
) -> u32 {
    let mut token_cursor = query;
    let mut total = 0u32;
    let mut is_first_token = true;

    loop {
        if token_cursor.read() == 0 {
            return total;
        }

        while token_cursor.read() == 0x20 {
            token_cursor = token_cursor.add(1);
        }

        let token = token_cursor;
        let mut token_len = 0u32;
        while token_cursor.read() != 0 && token_cursor.read() != 0x20 {
            token_cursor = token_cursor.add(1);
            token_len = token_len.wrapping_add(1);
        }

        if token_len != 0 {
            #[cfg(target_os = "none")]
            let score = retail_token_match_score(context, candidate, token, token_len);
            #[cfg(not(target_os = "none"))]
            let score = host_token_match_score(context, candidate, token, token_len);

            if score == 0 {
                return 0;
            }
            total = total.wrapping_add(if is_first_token && score == FIRST_TOKEN_EXACT_SCORE {
                FIRST_TOKEN_EXACT_BONUS
            } else {
                score
            });
        }

        is_first_token = false;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut SCORES: [u32; 4] = [0; 4];
    static mut TOKENS: [[u16; 5]; 4] = [[0; 5]; 4];
    static mut TOKEN_LENS: [u32; 4] = [0; 4];
    static mut CALL_COUNT: usize = 0;

    unsafe extern "C" fn record_score(
        _context: *mut u8,
        _candidate: *mut u8,
        token: *const u16,
        token_len: u32,
    ) -> u32 {
        let index = CALL_COUNT;
        CALL_COUNT = CALL_COUNT.wrapping_add(1);
        TOKEN_LENS[index] = token_len;
        for offset in 0..token_len as usize {
            TOKENS[index][offset] = token.add(offset).read();
        }
        SCORES[index]
    }

    fn install(scores: [u32; 4]) -> MutexGuard<'static, ()> {
        let guard = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(SCORES).write(scores);
            addr_of_mut!(TOKENS).write([[0; 5]; 4]);
            addr_of_mut!(TOKEN_LENS).write([0; 4]);
            addr_of_mut!(CALL_COUNT).write(0);
            addr_of_mut!(SEARCH_QUERY_TOKEN_SCORE_OPS).write(SearchQueryTokenScoreOps {
                score_token: record_score,
            });
        }
        guard
    }

    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            addr_of_mut!(SEARCH_QUERY_TOKEN_SCORE_OPS).write(DEFAULT_SEARCH_QUERY_TOKEN_SCORE_OPS);
        }
        drop(guard);
    }

    #[test]
    fn empty_and_space_only_queries_do_not_score() {
        let guard = install([0; 4]);
        let empty = [0u16];
        let spaces = [0x20u16, 0x20, 0];
        unsafe {
            assert_eq!(search_query_token_score(core::ptr::null_mut(), core::ptr::null_mut(), empty.as_ptr()), 0);
            assert_eq!(search_query_token_score(core::ptr::null_mut(), core::ptr::null_mut(), spaces.as_ptr()), 0);
            assert_eq!(addr_of!(CALL_COUNT).read(), 0);
        }
        restore(guard);
    }

    #[test]
    fn first_exact_token_receives_bonus_and_later_scores_sum() {
        let guard = install([1000, 1000, 10, 0]);
        let query = [0x20u16, b'a' as u16, b'l' as u16, b'p' as u16, b'h' as u16, b'a' as u16,
                     0x20, 0x20, b'b' as u16, b'e' as u16, b't' as u16, b'a' as u16, 0x20,
                     b'x' as u16, 0];
        unsafe {
            assert_eq!(search_query_token_score(0x12usize as *mut u8, 0x34usize as *mut u8, query.as_ptr()), 11010);
            assert_eq!(addr_of!(CALL_COUNT).read(), 3);
            assert_eq!(addr_of!(TOKEN_LENS).read(), [5, 4, 1, 0]);
            assert_eq!((&(*addr_of!(TOKENS))[0])[..5], [b'a' as u16, b'l' as u16, b'p' as u16, b'h' as u16, b'a' as u16]);
            assert_eq!((&(*addr_of!(TOKENS))[1])[..4], [b'b' as u16, b'e' as u16, b't' as u16, b'a' as u16]);
            assert_eq!((&(*addr_of!(TOKENS))[2])[..1], [b'x' as u16]);
        }
        restore(guard);
    }

    #[test]
    fn zero_token_score_short_circuits_remaining_tokens() {
        let guard = install([100, 0, 1000, 0]);
        let query = [b'a' as u16, 0x20, b'b' as u16, 0x20, b'c' as u16, 0];
        unsafe {
            assert_eq!(search_query_token_score(core::ptr::null_mut(), core::ptr::null_mut(), query.as_ptr()), 0);
            assert_eq!(addr_of!(CALL_COUNT).read(), 2);
            assert_eq!(addr_of!(TOKEN_LENS).read(), [1, 1, 0, 0]);
        }
        restore(guard);
    }
}
