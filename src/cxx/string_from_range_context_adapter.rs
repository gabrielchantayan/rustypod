//! `string_from_range_context_adapter` — original: `FUN_08110394` @
//! `0x08110394` (**8 bytes**, `0x08110394..0x0811039c`; the next independent
//! function begins with `push {r4, lr}` at `0x0811039c`). **3 plain `bl` call
//! sites, 0 predicated**, verified by decoding every A32 `bl` word in
//! `osos.dec`.
//!
//! Moves its third argument into `r1` and tail-branches to `string_from_range`
//! @ `0x080f020c`; its middle context argument is ignored. This adapts a
//! three-argument callback ABI to the converter's `(out, range)` ABI.
//!
//! # Deliberate deviations
//!
//! `string_from_range` remains unported. This uses the established volatile
//! `RANGE_I32_OPS` seam: target builds invoke its retail entry and host tests
//! install a fixture.

use crate::cxx::string_object::StringObject;
use crate::strto::range_i32::{RangeI32Ops, RANGE_I32_OPS};

#[inline(always)]
unsafe fn string_from_range_ops() -> RangeI32Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RANGE_I32_OPS)) }
}

/// Adapts a callback context and UTF-16 range to `string_from_range`.
///
/// # Safety
///
/// `out` and `range` must meet `string_from_range`'s unchecked retailOS
/// contract. `context` is intentionally neither read nor validated.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_from_range_context_adapter(
    out: *mut StringObject,
    _context: *mut u8,
    range: *const u8,
) {
    let ops = unsafe { string_from_range_ops() };
    unsafe { (ops.string_from_range)(out, range) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::strto::range_i32::{RANGE_I32_OPS_TEST_LOCK, Utf16RangeToStringFn};

    static mut OBSERVED_OUT: *mut StringObject = core::ptr::null_mut();
    static mut OBSERVED_RANGE: *const u8 = core::ptr::null();

    unsafe extern "C" fn converter_fixture(out: *mut StringObject, range: *const u8) {
        unsafe {
            OBSERVED_OUT = out;
            OBSERVED_RANGE = range;
        }
    }

    struct RangeOpsGuard(RangeI32Ops);

    impl Drop for RangeOpsGuard {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(self.0) };
        }
    }

    fn install_fixture() -> (std::sync::MutexGuard<'static, ()>, RangeOpsGuard) {
        let lock = RANGE_I32_OPS_TEST_LOCK.lock().unwrap();
        let saved = unsafe { core::ptr::addr_of!(RANGE_I32_OPS).read_volatile() };
        unsafe {
            core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(RangeI32Ops {
                string_from_range: converter_fixture as Utf16RangeToStringFn,
            });
            OBSERVED_OUT = core::ptr::null_mut();
            OBSERVED_RANGE = core::ptr::null();
        }
        (lock, RangeOpsGuard(saved))
    }

    #[test]
    fn forwards_unaligned_range_and_ignores_context() {
        let (_lock, _guard) = install_fixture();
        let mut out = core::mem::MaybeUninit::<StringObject>::uninit();
        let bytes = [0u8; 3];
        let range = unsafe { bytes.as_ptr().add(1) };

        unsafe {
            string_from_range_context_adapter(out.as_mut_ptr(), 1usize as *mut u8, range);
            assert_eq!(OBSERVED_OUT, out.as_mut_ptr());
            assert_eq!(OBSERVED_RANGE, range);
        }
    }

    #[test]
    fn forwards_null_range_without_inspecting_it() {
        let (_lock, _guard) = install_fixture();
        let mut out = core::mem::MaybeUninit::<StringObject>::uninit();

        unsafe {
            string_from_range_context_adapter(out.as_mut_ptr(), core::ptr::null_mut(), core::ptr::null());
            assert_eq!(OBSERVED_OUT, out.as_mut_ptr());
            assert!(OBSERVED_RANGE.is_null());
        }
    }
}
