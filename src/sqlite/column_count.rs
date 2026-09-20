//! SQLite result-column count accessor.
//!
//! `sqlite3_column_count` — original: `FUN_0838fa1c` @ `0x0838fa1c` (12
//! bytes; true extent `0x0838fa1c..0x0838fa28`). Raw ARM-word decoding finds
//! **3 direct `bl` call sites**, all unconditional (`0x08215a6c`,
//! `0x082c445c`, and `0x083903b4`), with **0 predicated `bl` call sites**.
//!
//! # Algorithm
//!
//! If the statement is non-NULL, return its signed `nResColumn` word at
//! +0xec. Otherwise return zero. The original has no other validation or
//! calls. No deliberate deviations.

use super::vdbe::Vdbe;

/// SQLite's `sqlite3_column_count` API.
///
/// # Safety
///
/// A non-NULL `statement` must point to a readable [`Vdbe`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite3_column_count(statement: *const Vdbe) -> i32 {
    if statement.is_null() {
        0
    } else {
        unsafe { (*statement).n_res_column }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn returns_zero_for_a_null_statement() {
        assert_eq!(unsafe { sqlite3_column_count(core::ptr::null()) }, 0);
    }

    #[test]
    fn returns_the_stored_signed_result_column_count() {
        let mut statement = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };

        for count in [-1, 0, 1, i32::MAX] {
            statement.n_res_column = count;
            assert_eq!(unsafe { sqlite3_column_count(&statement) }, count);
        }
    }
}
