//! SQLite expression-token dequoting.
//!
//! `dequote_expr_token` — original: `FUN_08375464` @ 0x08375464 (60 bytes;
//! 3 plain direct inbound `bl` call sites, binary-scanned). The true body ends
//! at 0x083754a0, where the next function begins.
//!
//! Algorithm: a +0x02 bit 0x40 marker makes the operation idempotent. On the
//! first invocation it sets that marker, duplicates the +0x14 token through
//! `token_copy` only when its packed ownership bit is clear, then tail-calls
//! `dequote` on the token text. The target's tail branch is represented by a
//! direct Rust call.
//!
//! Deliberate deviations: `Expr` and `Token` use shared `repr(C)` typed
//! layouts, preserving target-width offsets on ARM while avoiding host-pointer
//! width assumptions in tests.

use super::dequote::dequote;
use super::expr_new::Expr;
use super::token_copy::token_copy;

const TOKEN_DEQUOTED: u16 = 0x40;

/// Mark an expression token dequoted, own it when needed, then dequote it.
///
/// Original: `FUN_08375464` @ 0x08375464 (60 bytes; 3 plain direct inbound
/// `bl` call sites, binary-scanned).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dequote_expr_token(db: *mut u8, expression: *mut Expr) {
    if (*expression).flags & TOKEN_DEQUOTED != 0 {
        return;
    }

    (*expression).flags |= TOKEN_DEQUOTED;
    if (*expression).token.n_dyn & 1 == 0 {
        token_copy(db, &mut (*expression).token, &(*expression).token);
    }
    dequote((*expression).token.z as *mut u8);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::expr_new::Token;

    unsafe fn expression(token: Token, flags: u16) -> Expr {
        let mut expression: Expr = core::mem::zeroed();
        expression.flags = flags;
        expression.token = token;
        expression
    }

    #[test]
    fn marks_and_dequotes_an_owned_escaped_identifier() {
        let mut text = *b"'can''t'\0";
        let mut node = unsafe {
            expression(Token { z: text.as_ptr(), n_dyn: 1 }, 0)
        };

        unsafe { dequote_expr_token(core::ptr::null_mut(), &mut node) };

        assert_eq!(node.flags, TOKEN_DEQUOTED);
        assert_eq!(&text[..6], b"can't\0");
    }

    #[test]
    fn marked_token_is_left_unchanged() {
        let mut text = *b"'name'\0";
        let mut node = unsafe {
            expression(Token { z: text.as_ptr(), n_dyn: 1 }, TOKEN_DEQUOTED)
        };

        unsafe { dequote_expr_token(core::ptr::null_mut(), &mut node) };

        assert_eq!(&text, b"'name'\0");
        assert_eq!(node.flags, TOKEN_DEQUOTED);
    }

    #[test]
    fn null_text_is_marked_without_dequoting() {
        let mut node = unsafe {
            expression(Token { z: core::ptr::null(), n_dyn: 1 }, 0)
        };

        unsafe { dequote_expr_token(core::ptr::null_mut(), &mut node) };

        assert_eq!(node.flags, TOKEN_DEQUOTED);
        assert!(node.token.z.is_null());
    }
}
