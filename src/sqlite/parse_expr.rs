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
//! The callee is identified as SQLite 3.5.x's
//! `sqlite3Expr(db, op, pLeft, pRight, pToken)`: it allocates a 0x44-byte
//! `Expr` through the ported [`db_malloc_zero`](crate::sqlite::mem)
//! @ 0x08374998, stores the opcode byte at +0x00, the operands at
//! +0x08/+0x0c, `EP_CombBound`-style flag propagation off the children,
//! the token span as two words at +0x14/+0x18 (and +0x1c/+0x20), and
//! finishes with the height recomputation helper @ 0x083788fc. On
//! allocation failure it releases both operands through the expression
//! destructor @ 0x08377e00 and returns NULL. Every one of this adaptor's
//! 44 call sites is a grammar action building a tree node — e.g.
//! `parse_expr(pParse, 0x70 /*TK_LSHIFT*/, lhs, rhs, 0)`.
//!
//! Deviations:
//! - `sqlite3Expr` @ 0x08376808 is not ported (its operand-release and
//!   span-merge paths pull in the expression destructor chain); it is
//!   the [`SQLITE_EXPR_NEW`] dispatch boundary (house pattern — see
//!   `sqlite/error_msg.rs`). The default slot is a documented
//!   always-NULL stub — the same end state the original reaches when
//!   the 0x44-byte allocation fails, and what grammar actions already
//!   test for. The match.py diff is exactly that deviation: the Rust
//!   body tail-calls through the loaded slot instead of a direct `bl`.

/// A parse context (`sqlite3Parse`), only the field this adaptor
/// touches. The full layout is documented in `sqlite/mod.rs`; `db` at
/// +0x00 is the back-pointer every SQLite context struct starts with.
#[repr(C)]
pub struct Parse {
    /// +0x00: the owning connection (`sqlite3 *`).
    pub db: *mut u8,
}

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

/// Default stub: no constructor wired, so the node comes back NULL —
/// the same shape as a failed allocation inside the real constructor
/// (see the module header).
pub(crate) unsafe extern "C" fn missing_expr_new(
    _db: *mut u8,
    _op: i32,
    _left: *mut u8,
    _right: *mut u8,
    _token: *const u8,
) -> *mut u8 {
    core::ptr::null_mut()
}

/// The active expression constructor. Host tests install recording
/// mocks; the real port replaces the default when 0x08376808 lands.
pub static mut SQLITE_EXPR_NEW: ExprNewFn = missing_expr_new;

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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes access to the constructor slot across tests.
    static SLOT_LOCK: Mutex<()> = Mutex::new(());

    static mut CALLS: Vec<(usize, i32, usize, usize, usize)> = Vec::new();

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

    /// Puts the documented always-NULL stub back.
    fn restore_default() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(SQLITE_EXPR_NEW), missing_expr_new);
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
    fn the_default_stub_mimics_an_allocation_failure() {
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
    }
}
