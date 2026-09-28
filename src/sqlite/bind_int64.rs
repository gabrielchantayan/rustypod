//! 64-bit integer parameter binding.
//!
//! - `sqlite_bind_int64` — original: `FUN_0838ef84` @ 0x0838ef84
//!   (68 bytes, 0x0838ef84..0x0838efc8; **2 plain `bl` call sites, zero
//!   predicated `bl` call sites**), decoded from osos.dec.
//!
//! ### Algorithm
//!
//! SQLite's `sqlite3_bind_int64` validates and clears the selected one-based
//! host parameter through `vdbeUnbind`. On success it writes the supplied
//! signed 64-bit value into that parameter's `Mem` with
//! `sqlite3VdbeMemSetInt64`, then returns the validation result.
//!
//! ### Deliberate deviations
//!
//! The firmware computes `aVar + (index - 1) * 0x28` with raw 32-bit
//! pointers. This port uses the typed `Vdbe::a_var` array; its target layout
//! and 40-byte `Mem` stride are asserted in `sqlite/vdbe.rs`, while host
//! pointer widening remains safe.

use super::vdbe::Vdbe;
use super::vdbe_mem_set_int64::vdbe_mem_set_int64;
use super::vdbe_unbind::vdbe_unbind;

/// sqlite_bind_int64 — original: `FUN_0838ef84` @ 0x0838ef84 (68 bytes;
/// 2 plain `bl` call sites, zero predicated `bl` call sites).
///
/// SQLite's `sqlite3_bind_int64`: clear and validate `parameter_index` on
/// `statement`; if successful, replace that binding with `value` as an SQL
/// integer. The integer store is skipped for every validation failure.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sqlite_bind_int64(
    statement: *mut Vdbe,
    parameter_index: i32,
    value: i64,
) -> i32 {
    let result = vdbe_unbind(statement, parameter_index);
    if result == 0 {
        vdbe_mem_set_int64((*statement).a_var.add((parameter_index - 1) as usize), value);
    }
    result
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqlite::vdbe::{Mem, Vdbe};
    use crate::sqlite::vdbe_mem_set_int64::{
        tests::ops_lock, MemSetOps, DEFAULT_MEM_SET_OPS, MEM_SET_OPS,
    };
    use crate::sqlite::vdbe_unbind::{SQLITE_MISUSE, SQLITE_RANGE, VDBE_MAGIC_RUN};
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASE_ARG: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn recording_mem_release(value: *mut u8) {
        RELEASE_CALLS.fetch_add(1, Ordering::Relaxed);
        RELEASE_ARG.store(value as usize, Ordering::Relaxed);
    }

    struct OpsGuard;

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(MEM_SET_OPS).write(DEFAULT_MEM_SET_OPS) }
        }
    }

    fn record_releases() -> (std::sync::MutexGuard<'static, ()>, OpsGuard) {
        let lock = ops_lock().lock().unwrap_or_else(|error| error.into_inner());
        RELEASE_CALLS.store(0, Ordering::Relaxed);
        RELEASE_ARG.store(0, Ordering::Relaxed);
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_SET_OPS),
                MemSetOps {
                    mem_release: recording_mem_release,
                },
            );
        }
        (lock, OpsGuard)
    }

    fn empty_mem() -> Mem {
        unsafe { MaybeUninit::<Mem>::zeroed().assume_init() }
    }

    fn statement(values: &mut [Mem]) -> Vdbe {
        let mut statement = unsafe { MaybeUninit::<Vdbe>::zeroed().assume_init() };
        statement.magic = VDBE_MAGIC_RUN;
        statement.pc = -1;
        statement.n_var = values.len() as i32;
        statement.a_var = values.as_mut_ptr();
        statement
    }

    #[test]
    fn replaces_only_the_valid_one_based_binding_with_an_integer() {
        let _guards = record_releases();
        let mut values = [empty_mem(), empty_mem()];
        values[0].u = 0x1111;
        values[0].flags = 0xa1;
        values[1].u = 0x2222;
        values[1].flags = 0xb2;
        let mut statement = statement(&mut values);

        assert_eq!(unsafe { sqlite_bind_int64(&mut statement, 2, i64::MIN) }, 0);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(RELEASE_ARG.load(Ordering::Relaxed), core::ptr::addr_of!(values[1]) as usize);
        assert_eq!(values[0].u, 0x1111);
        assert_eq!(values[0].flags, 0xa1);
        assert_eq!(values[1].u, i64::MIN as u64);
        assert_eq!(values[1].flags, 4);
        assert_eq!(values[1].value_type, 1);
    }

    #[test]
    fn validation_failures_do_not_store_or_release_an_integer() {
        assert_eq!(unsafe { sqlite_bind_int64(core::ptr::null_mut(), 1, 7) }, SQLITE_MISUSE);

        let _guards = record_releases();
        let mut values = [empty_mem()];
        values[0].u = 0x1234;
        let mut statement = statement(&mut values);
        assert_eq!(unsafe { sqlite_bind_int64(&mut statement, 2, 7) }, SQLITE_RANGE);
        assert_eq!(RELEASE_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(values[0].u, 0x1234);
    }
}
