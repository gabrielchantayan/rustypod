//! SQLite expression-affinity recovery.

/// A SQLite parser token. `n_and_dyn` stores the one-bit ownership flag in bit
/// zero and the token length in the remaining 31 bits.
#[repr(C)]
pub struct Token {
    pub text: *const u8,
    pub n_and_dyn: u32,
}

/// The only `ExprList` item field reached through a `TK_SELECT` expression.
#[repr(C)]
pub struct ExprListItem {
    pub expr: *mut Expr,
}

/// SQLite's expression-list header. The retail layout has `items` at +0x0c.
#[repr(C)]
pub struct ExprList {
    pub count: i32,
    pub capacity: i32,
    pub cursor: i32,
    pub items: *mut ExprListItem,
}

/// The prefix of SQLite's `Select`; its result expression list is first.
#[repr(C)]
pub struct Select {
    pub expressions: *mut ExprList,
}

/// SQLite 3.5.9's recovered expression layout.
#[repr(C)]
pub struct Expr {
    pub op: u8,
    pub affinity: u8,
    pub flags: u16,
    pub collating_sequence: *mut u8,
    pub left: *mut Expr,
    pub right: *mut Expr,
    pub expression_list: *mut ExprList,
    pub token: Token,
    pub span: Token,
    pub table_cursor: i32,
    pub column: i32,
    pub aggregate_info: *mut u8,
    pub aggregate_index: i32,
    pub right_join_table: i32,
    pub select: *mut Select,
    pub table: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: () = {
    assert!(core::mem::offset_of!(Token, text) == 0x00);
    assert!(core::mem::offset_of!(Token, n_and_dyn) == 0x04);
    assert!(core::mem::size_of::<Token>() == 0x08);
    assert!(core::mem::offset_of!(ExprList, items) == 0x0c);
    assert!(core::mem::offset_of!(Expr, left) == 0x08);
    assert!(core::mem::offset_of!(Expr, token) == 0x14);
    assert!(core::mem::offset_of!(Expr, select) == 0x38);
};

const TK_CAST: u8 = 31;
const TK_SELECT: u8 = 110;
const AFFINITY_TEXT: u8 = b'a';
const AFFINITY_BLOB: u8 = b'b';
const AFFINITY_NUMERIC: u8 = b'c';
const AFFINITY_INTEGER: u8 = b'd';
const AFFINITY_REAL: u8 = b'e';

#[inline]
fn upper_to_lower(byte: u8) -> u8 {
    if byte >= b'A' && byte <= b'Z' {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}

/// The `sqlite3AffinityType` body reached by the retail function's `TK_CAST`
/// tail branch. It scans exactly `token.n_and_dyn >> 1` bytes.
unsafe fn affinity_type(token: *const Token) -> u8 {
    let mut affinity = AFFINITY_NUMERIC;
    let mut rolling = 0_u32;
    let text = (*token).text;
    let length = ((*token).n_and_dyn >> 1) as usize;

    for index in 0..length {
        rolling = (rolling << 8).wrapping_add(upper_to_lower(*text.add(index)) as u32);
        match rolling {
            0x6368_6172 | 0x636c_6f62 | 0x7465_7874 => affinity = AFFINITY_TEXT,
            0x626c_6f62 if affinity == AFFINITY_NUMERIC || affinity == AFFINITY_REAL => {
                affinity = AFFINITY_BLOB;
            }
            0x7265_616c | 0x666c_6f61 | 0x646f_7562 if affinity == AFFINITY_NUMERIC => {
                affinity = AFFINITY_REAL;
            }
            _ if rolling & 0x00ff_ffff == 0x0069_6e74 => return AFFINITY_INTEGER,
            _ => {}
        }
    }

    affinity
}

/// `expr_affinity` — original: `FUN_083768e0` @ `0x083768e0` (48 bytes).
///
/// Raw `osos.dec` words at `0x083768e0..0x0837690c` end at the independent
/// next entry `0x08376910`. Decoding every ARM B/BL immediate finds seven
/// direct inbound calls, all unconditional `bl` (zero predicated calls):
/// `0x082c3c1c`, `0x082c4724`, `0x082cd3d4`, `0x082cd3e8`, `0x083732c8`,
/// `0x083735c0`, and `0x08382448`. This is SQLite 3.5.9's
/// `sqlite3ExprAffinity`: a `TK_SELECT` (110) follows
/// `select->expressions->items[0].expr`; a `TK_CAST` (31) classifies its
/// token's bounded type name; every other expression returns its affinity
/// byte. Deliberate deviation: retail tail-branches to the unported 192-byte
/// `sqlite3AffinityType` at `0x0836e90c`; its verified byte-scan is inlined
/// here, avoiding a new dispatch seam while preserving the returned affinity.
///
/// # Safety
/// `expr` must name a valid SQLite expression. A `TK_SELECT` expression must
/// have a valid result-list, first item, and first-item expression. A
/// `TK_CAST` expression's token text must name `token.n_and_dyn >> 1` bytes.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_affinity(mut expr: *mut Expr) -> u8 {
    while (*expr).op == TK_SELECT {
        expr = (*(*(*(*expr).select).expressions).items).expr;
    }

    if (*expr).op == TK_CAST {
        affinity_type(core::ptr::addr_of!((*expr).token))
    } else {
        (*expr).affinity
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    unsafe fn blank_expr(op: u8, affinity: u8) -> Expr {
        let mut expr: Expr = core::mem::zeroed();
        expr.op = op;
        expr.affinity = affinity;
        expr
    }

    unsafe fn cast_affinity(type_name: &[u8]) -> u8 {
        let mut expr = blank_expr(TK_CAST, 0);
        expr.token.text = type_name.as_ptr();
        expr.token.n_and_dyn = (type_name.len() as u32) << 1;
        expr_affinity(core::ptr::addr_of_mut!(expr))
    }

    #[test]
    fn classifies_cast_type_names_case_insensitively() {
        unsafe {
            assert_eq!(cast_affinity(b"VARCHAR"), AFFINITY_TEXT);
            assert_eq!(cast_affinity(b"cLoB"), AFFINITY_TEXT);
            assert_eq!(cast_affinity(b"DOUBLE PRECISION"), AFFINITY_REAL);
            assert_eq!(cast_affinity(b"FLOATING POINT"), AFFINITY_INTEGER);
            assert_eq!(cast_affinity(b"INTEGER"), AFFINITY_INTEGER);
            assert_eq!(cast_affinity(b"BLOB"), AFFINITY_BLOB);
            assert_eq!(cast_affinity(b"UNSIGNED"), AFFINITY_NUMERIC);
        }
    }

    #[test]
    fn respects_packed_token_length_and_empty_type_name() {
        unsafe {
            let mut expr = blank_expr(TK_CAST, 0);
            expr.token.text = b"INTX".as_ptr();
            expr.token.n_and_dyn = (3 << 1) | 1;
            assert_eq!(expr_affinity(core::ptr::addr_of_mut!(expr)), AFFINITY_INTEGER);
            assert_eq!(cast_affinity(b""), AFFINITY_NUMERIC);
        }
    }

    #[test]
    fn select_uses_its_first_result_expression_affinity() {
        unsafe {
            let mut result = blank_expr(1, AFFINITY_REAL);
            let mut item = ExprListItem { expr: core::ptr::addr_of_mut!(result) };
            let mut expressions = ExprList {
                count: 1,
                capacity: 1,
                cursor: 0,
                items: core::ptr::addr_of_mut!(item),
            };
            let mut select = Select { expressions: core::ptr::addr_of_mut!(expressions) };
            let mut expr = blank_expr(TK_SELECT, AFFINITY_TEXT);
            expr.select = core::ptr::addr_of_mut!(select);

            assert_eq!(expr_affinity(core::ptr::addr_of_mut!(expr)), AFFINITY_REAL);
        }
    }

    #[test]
    fn direct_expression_returns_its_stored_affinity() {
        unsafe {
            let mut expr = blank_expr(1, 0);
            assert_eq!(expr_affinity(core::ptr::addr_of_mut!(expr)), 0);
            expr.affinity = AFFINITY_TEXT;
            assert_eq!(expr_affinity(core::ptr::addr_of_mut!(expr)), AFFINITY_TEXT);
        }
    }
}
