//! `string_from_range_provider` — original: `FUN_081d0d4c` @ `0x081d0d4c`
//! (**32 bytes**, `0x081d0d4c..0x081d0d68`; the separately linked helper begins
//! at `0x081d0d6c`). **10 plain `bl` call sites, 0 predicated**, verified by
//! decoding every ARM immediate `B`/`BL` word in `osos.dec`.
//!
//! Materializes the provider through vtable slot `+0x08`, then passes its
//! post-materialization two-word UTF-16 range at `this+0x0c` to the unported
//! `string_from_range` converter @ `0x080f020c`, writing directly to the
//! caller's StringObject. The wrapper has no NULL guard; either invalid pointer
//! faults in retailOS before conversion.
//!
//! # Deliberate deviations
//!
//! The sole direct call to separately linked `FUN_081d0d6c` is inlined: its
//! complete body is one virtual materialization followed by the two-word range
//! copy. The converter reuses the established `RANGE_I32_OPS` seam rather than
//! adding a duplicate dispatch boundary.

use crate::cxx::string_object::StringObject;
use crate::strto::range_i32::{RangeI32Ops, RANGE_I32_OPS};

/// ABI of vtable slot `+0x08`, which materializes a provider's range in place.
pub type MaterializeUtf16RangeFn = unsafe extern "C" fn(*mut Utf16RangeProvider);

/// The three vtable words read by the materialization wrapper.
///
/// The first two slot identities are opaque; slot `+0x08` is the only one the
/// original dereferences. `usize` and the function pointer are each one ARM
/// word on the firmware target.
#[repr(C)]
pub struct Utf16RangeProviderVtable {
    pub slot_0: usize,
    pub slot_4: usize,
    pub materialize: MaterializeUtf16RangeFn,
}

/// Prefix of the provider accepted by [`string_from_range_provider`].
///
/// On ARM, `range` starts at `this+0x0c`. The host pointer field naturally
/// widens under `repr(C)`, so tests use this named field rather than a literal
/// byte offset.
#[repr(C)]
pub struct Utf16RangeProvider {
    pub vtable: *const Utf16RangeProviderVtable,
    pub opaque_words: [u32; 2],
    pub range: [u32; 2],
}

#[inline(always)]
unsafe fn range_converter_ops() -> RangeI32Ops {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(RANGE_I32_OPS)) }
}

/// `string_from_range_provider` — original: `FUN_081d0d4c` @ `0x081d0d4c`.
///
/// Materializes `provider` through vtable slot `+0x08`, then converts its
/// resulting UTF-16 range into `out`. Neither pointer is validated, matching
/// the original's direct dereferences and indirect call.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.string_from_range_provider")]
#[inline(never)]
pub unsafe extern "C" fn string_from_range_provider(
    out: *mut StringObject,
    provider: *mut Utf16RangeProvider,
) {
    let materialize = unsafe { (*(*provider).vtable).materialize };
    unsafe { materialize(provider) };

    let range = unsafe { (*provider).range };
    let converter = unsafe { range_converter_ops().string_from_range };
    unsafe { converter(out, range.as_ptr().cast()) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;
    use crate::strto::range_i32::RANGE_I32_OPS_TEST_LOCK;
    use core::ptr;
    use std::sync::MutexGuard;

    static mut MATERIALIZE_CALLS: usize = 0;
    static mut MATERIALIZE_PROVIDER: usize = 0;
    static mut CONVERTER_CALLS: usize = 0;
    static mut CONVERTER_OUT: usize = 0;
    static mut CONVERTER_RANGE: usize = 0;
    static mut CONVERTER_WORDS: [u32; 2] = [0; 2];
    static mut WRONG_SLOT_CALLS: usize = 0;

    unsafe extern "C" fn wrong_slot() {
        unsafe { WRONG_SLOT_CALLS += 1 };
    }

    unsafe extern "C" fn materialize_fixture(provider: *mut Utf16RangeProvider) {
        unsafe {
            MATERIALIZE_CALLS += 1;
            MATERIALIZE_PROVIDER = provider as usize;
            (*provider).range = [0, u32::MAX];
        }
    }

    unsafe extern "C" fn converter_fixture(out: *mut StringObject, range: *const u8) {
        unsafe {
            CONVERTER_CALLS += 1;
            CONVERTER_OUT = out as usize;
            CONVERTER_RANGE = range as usize;
            CONVERTER_WORDS = range.cast::<u32>().cast::<[u32; 2]>().read();
            (*out).vtable = &STRING_OBJECT_VTABLE;
            (*out).payload = 0xdead_beefusize as *mut u8;
        }
    }

    struct RangeOpsGuard(RangeI32Ops);

    impl Drop for RangeOpsGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(self.0);
            }
        }
    }

    fn install_converter() -> (MutexGuard<'static, ()>, RangeOpsGuard) {
        let lock = RANGE_I32_OPS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let saved = core::ptr::addr_of!(RANGE_I32_OPS).read_volatile();
            core::ptr::addr_of_mut!(RANGE_I32_OPS).write_volatile(RangeI32Ops {
                string_from_range: converter_fixture,
                parse_decimal: saved.parse_decimal,
            });
            (lock, RangeOpsGuard(saved))
        }
    }

    #[test]
    fn materializes_only_slot_8_then_converts_the_post_materialization_range() {
        let (_lock, _ops) = install_converter();
        unsafe {
            MATERIALIZE_CALLS = 0;
            MATERIALIZE_PROVIDER = 0;
            CONVERTER_CALLS = 0;
            CONVERTER_OUT = 0;
            CONVERTER_RANGE = 0;
            CONVERTER_WORDS = [0; 2];
            WRONG_SLOT_CALLS = 0;
        }

        let vtable = Utf16RangeProviderVtable {
            slot_0: wrong_slot as usize,
            slot_4: wrong_slot as usize,
            materialize: materialize_fixture,
        };
        let mut provider = Utf16RangeProvider {
            vtable: &vtable,
            opaque_words: [0x1111_1111, 0x2222_2222],
            range: [0x3333_3333, 0x4444_4444],
        };
        let mut out = StringObject {
            vtable: ptr::null(),
            payload: ptr::null_mut(),
        };

        unsafe { string_from_range_provider(&mut out, &mut provider) };

        unsafe {
            assert_eq!(MATERIALIZE_CALLS, 1);
            assert_eq!(MATERIALIZE_PROVIDER, (&mut provider as *mut Utf16RangeProvider) as usize);
            assert_eq!(WRONG_SLOT_CALLS, 0, "only vtable slot +0x08 is dispatched");
            assert_eq!(CONVERTER_CALLS, 1);
            assert_eq!(CONVERTER_OUT, (&mut out as *mut StringObject) as usize);
            assert_ne!(CONVERTER_RANGE, provider.range.as_ptr() as usize, "the pair is copied to private stack storage");
            assert_eq!(CONVERTER_WORDS, [0, u32::MAX], "conversion sees materialized range");
        }
        assert_eq!(out.payload, 0xdead_beefusize as *mut u8);
    }
}
