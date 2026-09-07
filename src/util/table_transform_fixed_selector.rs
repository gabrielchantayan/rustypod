//! `table_transform_fixed_selector` — original: `FUN_0802b488` @ `0x0802b488`
//! (16 bytes).
//!
//! # Algorithm
//!
//! Four instructions, no frame: `mov r3, r2; mov r2, r1; ldr r1, =0x988a6f1f;
//! b 0x0802af9c`. The wrapper shifts its second and third arguments up one
//! register, binds the fixed selector `0x988a6f1f` as the callee's second
//! argument, and tail-branches into the 1260-byte body at `0x0802af9c`. As a
//! tail call, the body's `r0` is returned unchanged.
//!
//! The body is not ported. It is mixed-boolean-arithmetic obfuscated: the
//! selector is immediately rewritten as `r1 - 0xdd04c3a0`, which yields the
//! first word of the opaque-constant table at `0x0802b4a0` (`0xbb85ab7f`), and
//! every later decision is expressed through that table. What can be read
//! through the obfuscation is the shape: the third argument is a table base
//! indexed as `table[(k << 11) + (j << 10) + (byte << 2)]`, and the results are
//! written into a 160-byte stack buffer in a loop. No identity is inferred
//! for the body beyond that.
//!
//! On hardware the seam invokes the body's retailOS load address; host tests
//! install a recording seam to prove the argument shuffle, the bound selector,
//! the single call, and result propagation.

/// ABI of the obfuscated table transform body at retailOS `0x0802af9c`.
pub type TableTransformBody = unsafe extern "C" fn(u32, u32, u32, u32) -> u32;

/// RetailOS load address of the obfuscated table transform body.
pub const TABLE_TRANSFORM_BODY_ADDRESS: usize = 0x0802_af9c;

/// Selector word the wrapper binds as the body's second argument. Its only
/// legible property is the obfuscation relation below.
pub const FIXED_SELECTOR: u32 = 0x988a_6f1f;

/// The body's first rewrite of the selector: `selector - 0xdd04c3a0`.
pub const SELECTOR_REWRITE_SUBTRAHEND: u32 = 0xdd04_c3a0;

/// First word of the body's opaque-constant table at `0x0802b4a0`, which is
/// what the fixed selector rewrites to.
pub const OPAQUE_TABLE_FIRST_WORD: u32 = 0xbb85_ab7f;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_table_transform_body(
    context: u32,
    selector: u32,
    table: u32,
    arg: u32,
) -> u32 {
    let body: TableTransformBody = core::mem::transmute(TABLE_TRANSFORM_BODY_ADDRESS);
    body(context, selector, table, arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_table_transform_body(
    _context: u32,
    _selector: u32,
    _table: u32,
    _arg: u32,
) -> u32 {
    panic!("table_transform_fixed_selector requires body 0x0802af9c")
}

/// Active boundary for the unported body. On the target it calls directly
/// into retailOS; host tests replace it with a recording implementation.
#[cfg(target_os = "none")]
pub static mut TABLE_TRANSFORM_BODY: TableTransformBody = retail_table_transform_body;

/// Active host boundary for the unported body.
#[cfg(not(target_os = "none"))]
pub static mut TABLE_TRANSFORM_BODY: TableTransformBody = missing_table_transform_body;

#[inline(always)]
unsafe fn table_transform_body() -> TableTransformBody {
    core::ptr::read_volatile(core::ptr::addr_of!(TABLE_TRANSFORM_BODY))
}

/// table_transform_fixed_selector — original: `FUN_0802b488` @ `0x0802b488`
/// (16 bytes).
///
/// Calls the body at `0x0802af9c` as `body(context, 0x988a6f1f, table, arg)`
/// and returns its result, exactly as the stock tail branch does.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn table_transform_fixed_selector(context: u32, table: u32, arg: u32) -> u32 {
    table_transform_body()(context, FIXED_SELECTOR, table, arg)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut RECEIVED: [u32; 4] = [0; 4];
    static mut RETURN_VALUE: u32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn recording_body(context: u32, selector: u32, table: u32, arg: u32) -> u32 {
        RECEIVED = [context, selector, table, arg];
        CALLS += 1;
        RETURN_VALUE
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                TABLE_TRANSFORM_BODY = missing_table_transform_body;
                RECEIVED = [0; 4];
                RETURN_VALUE = 0;
                CALLS = 0;
            }
        }
    }

    #[test]
    fn binds_the_fixed_selector_between_context_and_table_and_returns_the_result() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        unsafe {
            TABLE_TRANSFORM_BODY = recording_body;
            RETURN_VALUE = 0x0bad_f00d;
            let result = table_transform_fixed_selector(0x11, 0x22, 0x33);
            assert_eq!(result, 0x0bad_f00d, "a tail call returns the body's r0 unchanged");
            assert_eq!(CALLS, 1, "the wrapper makes exactly one body call");
            assert_eq!(
                RECEIVED,
                [0x11, FIXED_SELECTOR, 0x22, 0x33],
                "r1/r2 shift up to r2/r3 and the literal fills r1"
            );
        }
    }

    #[test]
    fn forwards_every_bit_of_each_argument() {
        let _lock = SEAM_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _reset = Reset;
        unsafe {
            TABLE_TRANSFORM_BODY = recording_body;
            table_transform_fixed_selector(u32::MAX, 0, 0x8000_0001);
            assert_eq!(RECEIVED, [u32::MAX, FIXED_SELECTOR, 0, 0x8000_0001]);
        }
    }

    #[test]
    fn selector_rewrites_to_the_first_opaque_table_word() {
        // The body's first instruction on the selector is `sub r2, r1, #0xdd04c3a0`;
        // the bound literal is chosen so that lands exactly on the table head.
        assert_eq!(
            FIXED_SELECTOR.wrapping_sub(SELECTOR_REWRITE_SUBTRAHEND),
            OPAQUE_TABLE_FIRST_WORD
        );
    }
}
