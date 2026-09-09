//! The expression code generator's temporary-register wrapper.
//!
//! - `expr_code_temp` — original: `FUN_08377b9c` @ 0x08377b9c (84 bytes;
//!   16 unconditional `bl` call sites, binary-scanned; no predicated calls
//!   and no tail `b` sites). SQLite 3.5.9's `sqlite3ExprCodeTemp` (expr.c).
//!   It asks the expression code generator to use a newly allocated temporary
//!   VDBE register, retaining that register only when the generator honors the
//!   request.
//!
//! Firmware algorithm (verified against osos.dec 0x08377b9c..0x08377bf0):
//!
//! ```text
//! temp_reg = get_temp_reg(parse)                         // 0x0837a3bc
//! in_reg = expr_code_target(parse, expr, temp_reg)       // 0x08376ef0
//! if in_reg == temp_reg:
//!     *out_temp_reg = temp_reg
//! else:
//!     release_temp_reg(parse, temp_reg)                   // 0x08381f98
//!     *out_temp_reg = 0
//! return in_reg
//! ```
//!
//! Deliberate deviation: `expr_code_target` is still unported, so this uses
//! the existing [`super::expr_code::EXPR_CODE_OPS`] dispatch seam rather than
//! inventing another one. Its shipped target and host default reports that the
//! value already occupies `temp_reg`.

/// expr_code_temp — original: `FUN_08377b9c` @ 0x08377b9c (84 bytes;
/// 16 unconditional `bl` call sites).
///
/// `sqlite3ExprCodeTemp`: allocate a temporary VDBE register and request that
/// the expression generator place `expr` there. If it instead returns another
/// register, recycle the unused temporary and store SQLite's zero register
/// sentinel in `out_temp_reg`; otherwise store the allocated register. The
/// generator's register is always returned. `out_temp_reg` has no NULL guard,
/// matching the original final `str` on both paths.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn expr_code_temp(
    parse: *mut u8,
    expr: *mut u8,
    out_temp_reg: *mut i32,
) -> i32 {
    let temp_reg = super::get_temp_reg::get_temp_reg(parse);
    let in_reg = (super::expr_code::expr_code_target_op())(parse, expr, temp_reg);
    if in_reg == temp_reg {
        out_temp_reg.write(temp_reg);
    } else {
        super::parse::release_temp_reg(parse, temp_reg);
        out_temp_reg.write(0);
    }
    in_reg
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sqlite::expr_code::{ExprCodeOps, DEFAULT_EXPR_CODE_OPS, EXPR_CODE_OPS, EXPR_CODE_OPS_LOCK};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    static mut CALLS: Vec<(*mut u8, *mut u8, i32)> = Vec::new();
    static mut MOCK_IN_REG: i32 = 0;

    unsafe extern "C" fn recording_expr_code_target(
        parse: *mut u8,
        expr: *mut u8,
        target: i32,
    ) -> i32 {
        (*core::ptr::addr_of_mut!(CALLS)).push((parse, expr, target));
        *core::ptr::addr_of!(MOCK_IN_REG)
    }

    /// Restores the default before releasing the shared seam lock, including
    /// when an assertion aborts a test.
    struct ResetExprCodeOps;

    impl Drop for ResetExprCodeOps {
        fn drop(&mut self) {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!(EXPR_CODE_OPS),
                    DEFAULT_EXPR_CODE_OPS,
                );
            }
        }
    }

    fn install(in_reg: i32) -> (MutexGuard<'static, ()>, ResetExprCodeOps) {
        let guard = EXPR_CODE_OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(CALLS)).clear();
            *core::ptr::addr_of_mut!(MOCK_IN_REG) = in_reg;
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(EXPR_CODE_OPS),
                ExprCodeOps {
                    expr_code_target: recording_expr_code_target,
                },
            );
        }
        (guard, ResetExprCodeOps)
    }

    fn calls() -> Vec<(*mut u8, *mut u8, i32)> {
        unsafe { (*core::ptr::addr_of!(CALLS)).clone() }
    }

    #[repr(align(4))]
    struct ParseContext([u8; 0x4c]);

    impl ParseContext {
        fn new(n_mem: i32) -> Self {
            let mut parse = ParseContext([0xa5; 0x4c]);
            parse.0[super::super::get_temp_reg::N_TEMP_REG_OFFSET] = 0;
            unsafe {
                (parse.0.as_mut_ptr().add(super::super::get_temp_reg::N_MEM_OFFSET) as *mut i32)
                    .write(n_mem);
            }
            parse
        }

        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }

        fn n_mem(&self) -> i32 {
            unsafe {
                (self.0.as_ptr().add(super::super::get_temp_reg::N_MEM_OFFSET) as *const i32).read()
            }
        }

        fn temp_count(&self) -> u8 {
            self.0[super::super::get_temp_reg::N_TEMP_REG_OFFSET]
        }

        fn temp_slot(&self, index: usize) -> i32 {
            unsafe {
                (self.0.as_ptr().add(super::super::get_temp_reg::A_TEMP_REG_OFFSET) as *const i32)
                    .add(index)
                    .read()
            }
        }
    }

    const EXPR_COOKIE: usize = 0x5eed;

    #[test]
    fn retained_temp_register_is_reported_to_caller() {
        let (_guard, _reset) = install(41);
        let mut parse = ParseContext::new(40);
        let mut out_temp_reg = 0;
        let result = unsafe {
            expr_code_temp(parse.ptr(), EXPR_COOKIE as *mut u8, &mut out_temp_reg)
        };

        assert_eq!(result, 41);
        assert_eq!(out_temp_reg, 41);
        assert_eq!(parse.n_mem(), 41, "get_temp_reg increments nMem once");
        assert_eq!(parse.temp_count(), 0, "the retained register is not released");
        assert_eq!(calls(), [(parse.ptr(), EXPR_COOKIE as *mut u8, 41)]);
    }

    #[test]
    fn rejected_temp_register_is_released_and_output_is_zero() {
        let (_guard, _reset) = install(-7);
        let mut parse = ParseContext::new(40);
        let mut out_temp_reg = 123;
        let result = unsafe {
            expr_code_temp(parse.ptr(), EXPR_COOKIE as *mut u8, &mut out_temp_reg)
        };

        assert_eq!(result, -7, "the generator's register is returned verbatim");
        assert_eq!(out_temp_reg, 0, "zero is SQLite's no-temp-register sentinel");
        assert_eq!(parse.n_mem(), 41);
        assert_eq!(parse.temp_count(), 1);
        assert_eq!(parse.temp_slot(0), 41, "the unused allocated register is recycled");
        assert_eq!(calls(), [(parse.ptr(), EXPR_COOKIE as *mut u8, 41)]);
    }

    #[test]
    fn wrapped_temp_register_is_retained_when_generator_agrees() {
        let (_guard, _reset) = install(i32::MIN);
        let mut parse = ParseContext::new(i32::MAX);
        let mut out_temp_reg = 0;
        let result = unsafe {
            expr_code_temp(parse.ptr(), EXPR_COOKIE as *mut u8, &mut out_temp_reg)
        };

        assert_eq!(result, i32::MIN);
        assert_eq!(out_temp_reg, i32::MIN);
        assert_eq!(parse.n_mem(), i32::MIN, "ARM add wraps at i32::MAX");
        assert_eq!(parse.temp_count(), 0);
        assert_eq!(calls(), [(parse.ptr(), EXPR_COOKIE as *mut u8, i32::MIN)]);
    }
}
