//! SQLite expression integer recognition — `sqlite3ExprIsInteger`.
//!
//! - Load address: `0x0837850c`
//! - True size: 112 bytes (`0x0837850c..0x0837857c`); `0x0837857c` begins
//!   the next real function.
//! - Calls: 2 unconditional plain `bl` instructions (self at `0x08378550`,
//!   `sqlite3GetInt32` at `0x08378538`); no predicated `bl` instructions.
//!
//! The routine strips any number of unary-plus expression nodes, recursively
//! recognizes a unary-minus child and negates its result, or parses an integer
//! literal token through retail `sqlite3GetInt32`. Deliberate deviation: the
//! retail `sqlite3GetInt32` call remains an address seam until that callee is
//! ported; host tests install a recorder seam.

const UNARY_MINUS: u8 = b'U';
const UNARY_PLUS: u8 = b'V';
const INTEGER_LITERAL: u8 = b'|';
const CHILD_OFFSET: usize = 0x08;
const TOKEN_OFFSET: usize = 0x14;
#[cfg(target_os = "none")]
const SQLITE_GET_INT32_ADDRESS: usize = 0x0837_a28c;

type SqliteGetInt32 = unsafe extern "C" fn(*const u8, *mut i32) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_sqlite_get_int32(token: *const u8, value: *mut i32) -> i32 {
    unsafe { core::mem::transmute::<usize, SqliteGetInt32>(SQLITE_GET_INT32_ADDRESS)(token, value) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sqlite_get_int32(_: *const u8, _: *mut i32) -> i32 {
    panic!("sqlite_expr_is_integer requires a sqlite_get_int32 fixture")
}

#[cfg(not(target_os = "none"))]
pub static mut SQLITE_GET_INT32: SqliteGetInt32 = missing_sqlite_get_int32;

#[inline(always)]
unsafe fn expression_word(expression: *const u8, offset: usize) -> u32 {
    unsafe { (expression.add(offset) as *const u32).read_volatile() }
}

#[inline(always)]
unsafe fn sqlite_get_int32(token: *const u8, value: *mut i32) -> i32 {
    #[cfg(target_os = "none")]
    { unsafe { retail_sqlite_get_int32(token, value) } }
    #[cfg(not(target_os = "none"))]
    { unsafe { SQLITE_GET_INT32(token, value) } }
}

/// `sqlite3ExprIsInteger` @ `0x0837850c`: recognize a signed integer Expr.
///
/// `expression` must use the retail 32-bit Expr layout: its child and token
/// pointers are words at `+0x08` and `+0x14`. `initial_value` is preserved as
/// the recursive local's initial value, exactly as the retail stack frame.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_expr_is_integer(
    mut expression: *const u8,
    value: *mut i32,
    _unused: u32,
    initial_value: i32,
) -> i32 {
    loop {
        match unsafe { expression.read_volatile() } {
            UNARY_PLUS => expression = unsafe { expression_word(expression, CHILD_OFFSET) as usize as *const u8 },
            UNARY_MINUS => {
                let mut child_value = initial_value;
                if unsafe { sqlite_expr_is_integer(expression_word(expression, CHILD_OFFSET) as usize as *const u8, &mut child_value, _unused, initial_value) } != 0 {
                    unsafe { value.write_volatile(child_value.wrapping_neg()) };
                    return 1;
                }
                return 0;
            }
            INTEGER_LITERAL => return i32::from(unsafe { sqlite_get_int32(expression_word(expression, TOKEN_OFFSET) as usize as *const u8, value) } != 0),
            _ => return 0,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static PARSE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static PARSED_VALUE: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn parse_fixture(token: *const u8, value: *mut i32) -> i32 {
        PARSE_CALLS.fetch_add(1, Ordering::SeqCst);
        match unsafe { token.read() } {
            b'9' => {
                unsafe { value.write(PARSED_VALUE.load(Ordering::SeqCst)) };
                1
            }
            b'2' => 2,
            _ => 0,
        }
    }

    unsafe fn word(base: *mut u8, offset: usize, value: *const u8) {
        unsafe { (base.add(offset) as *mut u32).write_volatile(value as usize as u32) };
    }

    #[test]
    fn recognizes_literal_and_nested_signed_unary_expressions() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::SQLITE_EXPR_IS_INTEGER, 0x1000) else { return; };
        unsafe { SQLITE_GET_INT32 = parse_fixture };
        PARSED_VALUE.store(9, Ordering::SeqCst);

        let plus = slab;
        let minus = unsafe { slab.add(0x40) };
        let literal = unsafe { slab.add(0x80) };
        let token = unsafe { slab.add(0x100) };
        unsafe {
            plus.write(b'V');
            minus.write(b'U');
            literal.write(b'|');
            token.write(b'9');
            word(plus, CHILD_OFFSET, minus);
            word(minus, CHILD_OFFSET, literal);
            word(literal, TOKEN_OFFSET, token);
        }

        let mut value = 0;
        assert_eq!(unsafe { sqlite_expr_is_integer(plus, &mut value, 0xfeed_beef, 123) }, 1);
        assert_eq!(value, -9);
        assert_eq!(PARSE_CALLS.swap(0, Ordering::SeqCst), 1);

        unsafe { plus.write(b'U') };
        assert_eq!(unsafe { sqlite_expr_is_integer(plus, &mut value, 0, 0) }, 1);
        assert_eq!(value, 9);
        unsafe { token.write(b'2') };
        assert_eq!(unsafe { sqlite_expr_is_integer(literal, &mut value, 0, 0) }, 1);
    }

    #[test]
    fn preserves_output_when_literal_parse_fails_or_tag_is_unknown() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(crate::testing::hints::SQLITE_EXPR_IS_INTEGER_FAILURE, 0x1000) else { return; };
        unsafe { SQLITE_GET_INT32 = parse_fixture };
        let literal = slab;
        let token = unsafe { slab.add(0x100) };
        unsafe {
            literal.write(b'|');
            token.write(b'x');
            word(literal, TOKEN_OFFSET, token);
        }
        let mut value = 77;
        assert_eq!(unsafe { sqlite_expr_is_integer(literal, &mut value, 0, 0) }, 0);
        assert_eq!(value, 77);
        unsafe { literal.write(b'?') };
        assert_eq!(unsafe { sqlite_expr_is_integer(literal, &mut value, 0, 0) }, 0);
        assert_eq!(PARSE_CALLS.swap(0, Ordering::SeqCst), 1);
    }
}
