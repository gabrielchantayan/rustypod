//! The parser's expression-constructor front-end — a five-argument
//! adaptor that sits between the grammar actions and the expression
//! allocator.
//!
//! - `parse_expr` — original: `FUN_0837dc18` @ 0x0837dc18 (32 bytes;
//!   44 `bl` call sites, binary-scanned). SQLite's `sqlite3PExpr`.
//!
//! Algorithm: replace the first argument with the `db` back-pointer at
//! +0x00 of the parse context and tail-call the expression constructor
//! `sqlite3Expr` @ 0x08376808 with the remaining four arguments,
//! shuffling the fifth (the token) through the stack. Pure forwarding:
//!
//! ```text
//! 0837dc18:  mov r12,r3           ; park pRight
//! 0837dc1c:  stmdb sp!,{r3,lr}
//! 0837dc20:  ldr r3,[sp,#0x8]     ; reload the caller's 5th arg (token)
//! 0837dc24:  str r3,[sp,#0x0]     ; ... and pass it on as our 5th arg
//! 0837dc28:  ldr r0,[r0,#0x0]     ; parse -> parse->db
//! 0837dc2c:  mov r3,r12
//! 0837dc30:  bl 0x08376808        ; sqlite3Expr(db, op, left, right, token)
//! 0837dc34:  ldmia sp!,{r12,pc}   ; r0 (the new Expr*) falls through
//! ```
//!
//! The callee is SQLite 3.5.x's
//! `sqlite3Expr(db, op, pLeft, pRight, pToken)` — **ported** as
//! [`crate::sqlite::expr_new::expr_new`]: it allocates a 0x44-byte
//! `Expr` through the ported [`db_malloc_zero`](crate::sqlite::mem)
//! @ 0x08374998, stores the opcode byte at +0x00, the operands at
//! +0x08/+0x0c, `EP_CombBound`-style flag propagation off the children,
//! the token span as two words at +0x14/+0x18 (and +0x1c/+0x20), and
//! finishes with the height recomputation helper @ 0x083788fc (the
//! ported [`crate::sqlite::expr_height::expr_set_height`]). On
//! allocation failure it releases both operands through the expression
//! destructor @ 0x08377e00 and returns NULL. Every one of this
//! adaptor's 44 call sites is a grammar action building a tree node —
//! e.g. `parse_expr(pParse, 0x70 /*TK_LSHIFT*/, lhs, rhs, 0)`.
//!
//! Deviations:
//! - The call to `sqlite3Expr` keeps the dispatch-slot shape (house
//!   pattern — see `sqlite/error_msg.rs`) so host tests can swap in
//!   recording mocks: [`SQLITE_EXPR_NEW`] now defaults to the real
//!   port, [`crate::sqlite::expr_new::expr_new`];
//!   [`missing_expr_new`], the documented always-NULL stub that used to
//!   fill the slot, is retained for the host tests — its behavior is
//!   *exactly* the end state the original reaches when the 0x44-byte
//!   allocation fails, and what grammar actions already test for. The
//!   match.py diff is exactly this deviation: the Rust body tail-calls
//!   through the loaded slot instead of a direct `bl`.

/// A parse context (`sqlite3Parse`), only the field this adaptor
/// touches. The full layout is documented in `sqlite/mod.rs`; `db` at
/// +0x00 is the back-pointer every SQLite context struct starts with.
#[repr(C)]
pub struct Parse {
    /// +0x00: the owning connection (`sqlite3 *`).
    pub db: *mut u8,
}

use super::expr_new::{expr_new, Token};

/// The expression constructor: `sqlite3Expr(db, op, left, right,
/// token)` @ 0x08376808. Returns the new `Expr *`, or NULL when its
/// allocation fails (after releasing both operands).
pub type ExprNewFn = unsafe extern "C" fn(
    db: *mut u8,
    op: i32,
    left: *mut u8,
    right: *mut u8,
    token: *const u8,
) -> *mut u8;

/// Default stub while 0x08376808 was unported; the slot now defaults
/// to the real port (see the module header). Retained for the host
/// tests: no constructor wired, so the node comes back NULL — the same
/// shape as a failed allocation inside the real constructor.
#[allow(dead_code)] // test-only since 0x08376808 was ported
pub(crate) unsafe extern "C" fn missing_expr_new(
    _db: *mut u8,
    _op: i32,
    _left: *mut u8,
    _right: *mut u8,
    _token: *const u8,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// The active expression constructor. The default is the real port,
/// [`expr_new`]; host tests still install recording mocks through the
/// slot.
pub static mut SQLITE_EXPR_NEW: ExprNewFn = expr_new;

/// Reads the constructor slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) fn expr_new_op() -> ExprNewFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SQLITE_EXPR_NEW)) }
}

/// parse_expr — original: `FUN_0837dc18` @ 0x0837dc18 (32 bytes;
/// 44 `bl` call sites).
///
/// `sqlite3PExpr`: build an expression node on behalf of a grammar
/// action. Identical to `sqlite3Expr` except the parse context stands
/// in for the connection: `db` is read from `parse` +0x00 and `op`,
/// `left`, `right` and `token` are forwarded untouched (the original
/// passes `op` as a full register; the callee stores its low byte).
/// Returns whatever the constructor returns — the new `Expr *`, or
/// NULL on allocation failure.
///
/// Register usage: r0 = parse, r1 = op, r2 = left, r3 = right,
/// `[sp]` = token (the AAPCS 5th argument, relayed stack-to-stack).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_expr(
    parse: *mut Parse,
    op: i32,
    left: *mut u8,
    right: *mut u8,
    token: *const u8,
) -> *mut u8 {
    (expr_new_op())((*parse).db, op, left, right, token)
}

/// parse_identifier_expr — original: `FUN_08373ccc` @ 0x08373ccc
/// (48 bytes; 6 `bl` call sites, binary-scanned).
///
/// SQLite grammar helper for an identifier expression. It initializes a
/// stack `Token` from the NUL-terminated `text`: `z` is retained verbatim
/// and `n_dyn` is the byte length shifted left one (dynamic ownership bit
/// clear). It then constructs `TK_ID` (`0x17`) with no operands through
/// [`parse_expr`], returning that constructor result unchanged.
///
/// Raw ARM contains two unconditional calls: the token initializer at
/// 0x08369074 and [`parse_expr`] at 0x0837dc18. The former is not separately
/// ported, so its verified byte-at-a-time `strlen` and two-word `Token`
/// initialization are inlined here; volatile byte loads keep LLVM from
/// replacing that loop with an unavailable libc `strlen`. The raw scan finds
/// six inbound calls, all unconditional plain `bl`: 0x082b2dbc,
/// 0x082b2dcc, 0x082b2de4, 0x082b2dfc, 0x08396330, and 0x083963b4.
///
/// Register usage: r0 = `Parse *`, r1 = identifier text. r2/r3 are saved
/// incidentally by the prologue and otherwise unused.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_identifier_expr(parse: *mut Parse, text: *const u8) -> *mut u8 {
    let mut token = Token {
        z: text,
        n_dyn: 0,
    };
    if !text.is_null() {
        let mut cursor = text;
        loop {
            if core::ptr::read_volatile(cursor) == 0 {
                break;
            }
            token.n_dyn = token.n_dyn.wrapping_add(2);
            cursor = cursor.add(1);
        }
    }
    parse_expr(
        parse,
        0x17,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::addr_of!(token) as *const u8,
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes access to the constructor slot across tests.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    static mut CALLS: Vec<(usize, i32, usize, usize, usize)> = Vec::new();

    static mut IDENTIFIER_CALLS: Vec<(usize, i32, usize, usize, usize, u32)> = Vec::new();

    /// Records every argument and hands back a fixed "new node".
    unsafe extern "C" fn recording_expr_new(
        db: *mut u8,
        op: i32,
        left: *mut u8,
        right: *mut u8,
        token: *const u8,
    ) -> *mut u8 {
        (*core::ptr::addr_of_mut!(CALLS)).push((
            db as usize,
            op,
            left as usize,
            right as usize,
            token as usize,
        ));
        0x600dc0de as *mut u8
    }

    /// Installs the recorder; the guard restores the default stub on
    /// drop. One guard per test — never shadowed.
    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_NEW), recording_expr_new);
        }
        guard
    }

    fn calls() -> Vec<(usize, i32, usize, usize, usize)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    /// Records the complete token synthesized by `parse_identifier_expr`.
    unsafe extern "C" fn recording_identifier_expr_new(
        db: *mut u8,
        op: i32,
        left: *mut u8,
        right: *mut u8,
        token: *const u8,
    ) -> *mut u8 {
        let token = &*(token as *const Token);
        (*core::ptr::addr_of_mut!(IDENTIFIER_CALLS)).push((
            db as usize,
            op,
            left as usize,
            right as usize,
            token.z as usize,
            token.n_dyn,
        ));
        0x600dc0de as *mut u8
    }

    fn install_identifier_recorder() -> MutexGuard<'static, ()> {
        let guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(IDENTIFIER_CALLS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(SQLITE_EXPR_NEW),
                recording_identifier_expr_new,
            );
        }
        guard
    }

    fn identifier_calls() -> Vec<(usize, i32, usize, usize, usize, u32)> {
        unsafe { (*core::ptr::addr_of!(IDENTIFIER_CALLS)).clone() }
    }

    /// Puts the shipped default — the real `sqlite3Expr` port — back.
    fn restore_default() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_NEW), expr_new);
        }
    }

    #[test]
    fn the_first_argument_becomes_the_db_back_pointer() {
        let _guard = install_recorder();
        let mut conn = [0u8; 8];
        let mut parse = Parse { db: conn.as_mut_ptr() };
        let token = [0xabu8; 4];

        let node = unsafe {
            parse_expr(
                &mut parse,
                0x70,
                0x11111111 as *mut u8,
                0x22222222 as *mut u8,
                token.as_ptr(),
            )
        };

        assert_eq!(
            calls(),
            std::vec![(
                conn.as_mut_ptr() as usize,
                0x70,
                0x11111111,
                0x22222222,
                token.as_ptr() as usize,
            )],
            "arg0 is *parse, the other four arguments pass through verbatim"
        );
        assert_eq!(node, 0x600dc0de as *mut u8, "the constructor's return falls through");
        restore_default();
    }

    #[test]
    fn null_operands_and_token_are_forwarded_untouched() {
        let _guard = install_recorder();
        let mut parse = Parse {
            db: core::ptr::null_mut(),
        };

        let node = unsafe {
            parse_expr(
                &mut parse,
                0x17,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
        };

        assert_eq!(calls(), std::vec![(0, 0x17, 0, 0, 0)]);
        assert_eq!(node, 0x600dc0de as *mut u8);
        restore_default();
    }

    #[test]
    fn identifier_text_stops_at_nul_and_packs_its_length() {
        let _guard = install_identifier_recorder();
        let mut db = [0u8; 8];
        let mut parse = Parse { db: db.as_mut_ptr() };
        let text = *b"row\0ignored";

        let node = unsafe { parse_identifier_expr(&mut parse, text.as_ptr()) };

        assert_eq!(node, 0x600dc0de as *mut u8);
        assert_eq!(
            identifier_calls(),
            std::vec![(db.as_mut_ptr() as usize, 0x17, 0, 0, text.as_ptr() as usize, 6)],
            "the token initializer retains z and stores strlen(z) << 1"
        );
        restore_default();
    }

    #[test]
    fn null_identifier_text_remains_a_present_empty_token() {
        let _guard = install_identifier_recorder();
        let mut parse = Parse {
            db: core::ptr::null_mut(),
        };

        let node = unsafe { parse_identifier_expr(&mut parse, core::ptr::null()) };

        assert_eq!(node, 0x600dc0de as *mut u8);
        assert_eq!(
            identifier_calls(),
            std::vec![(0, 0x17, 0, 0, 0, 0)],
            "the wrapper passes &Token even when Token.z is NULL"
        );
        restore_default();
    }

    #[test]
    fn the_missing_stub_mimics_an_allocation_failure() {
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_NEW), missing_expr_new);
        }
        let mut parse = Parse {
            db: 0xdead as *mut u8,
        };

        let node = unsafe {
            parse_expr(&mut parse, 0x6b, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null())
        };

        assert!(node.is_null(), "no constructor wired: NULL, like OOM");
        restore_default();
    }

    #[test]
    fn the_shipped_default_is_the_real_port() {
        use super::super::mem::tests::{install_recorder, Connection};
        use super::super::mem::{DB_MEM_OPS, DEFAULT_DB_MEM_OPS};
        let _guard = SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        restore_default();
        // 96 zeroed, aligned bytes: on a 64-bit host the constructor's
        // height fix-up reaches past the original's 0x44-byte request
        // (the widened Expr's p_select/n_height), so the arena covers
        // the widened struct with a NULL p_select.
        let mut arena = [0u64; 12];
        let _ops = install_recorder(arena.as_mut_ptr() as *mut u8);
        let mut conn = Connection::healthy();
        let mut parse = Parse { db: conn.ptr() };

        let node = unsafe {
            parse_expr(&mut parse, 0x70, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null())
        };

        assert_eq!(node, arena.as_mut_ptr() as *mut u8, "the real constructor's allocation comes back");
        assert_eq!(unsafe { *node }, 0x70, "and its op byte (+0x00) is the opcode's low half");
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(DB_MEM_OPS), DEFAULT_DB_MEM_OPS);
        }
    }
}
