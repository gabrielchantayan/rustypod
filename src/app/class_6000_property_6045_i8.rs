//! `class6000_property_6045_i8` — original: `FUN_08171a80` @ `0x08171a80`
//! (40 bytes: 10 ARM instructions through `0x08171aa4`, followed by the
//! `0x55693332` literal at `0x08171aa8`; the next function starts at
//! `0x08171aac`). **5 `bl` call sites**, independently binary-scanned as
//! ARM branch-with-link encodings: all five are plain unconditional `bl`
//! instructions; there are no predicated `bl` call sites.
//!
//! Calls the class-0x6000 store's vtable slot +0xe0 with property key 0x6045,
//! class id 0x6000, and resource kind `"23iU"`. It returns the low byte of
//! the slot result, sign-extended to i32.
//!
//! Deliberate deviation: the stock `blx` virtual dispatch is represented as a
//! Rust call. The shared slot type models its result as a pointer for its
//! typed-property callers; this routine preserves the firmware's raw `r0`
//! interpretation by taking that result's low byte without dereferencing it.

use crate::app::class_8900::Class6000;
use crate::app::resource_chain::ResourceKind;

const CLASS_ID_6000: u32 = 0x6000;
const PROPERTY_KEY_6045: u32 = 0x6045;
const RESOURCE_KIND_23IU: ResourceKind = ResourceKind(0x5569_3332);

/// Reads signed property 0x6045 from a class-0x6000 store.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class6000_property_6045_i8(store: *mut Class6000) -> i32 {
    let read_typed = (*(*store).vtable).read_typed;
    (read_typed(store, PROPERTY_KEY_6045, CLASS_ID_6000, RESOURCE_KIND_23IU) as usize as u8 as i8)
        as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static OBSERVED_KEY: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_CLASS: AtomicU32 = AtomicU32::new(0);
    static OBSERVED_KIND: AtomicU32 = AtomicU32::new(0);
    static RAW_RESULT: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn read_typed_result(
        _store: *mut Class6000,
        key: u32,
        class_id: u32,
        kind: ResourceKind,
    ) -> *mut u32 {
        OBSERVED_KEY.store(key, Ordering::Relaxed);
        OBSERVED_CLASS.store(class_id, Ordering::Relaxed);
        OBSERVED_KIND.store(kind.0, Ordering::Relaxed);
        RAW_RESULT.load(Ordering::Relaxed) as usize as *mut u32
    }

    #[test]
    fn forwards_typed_property_request_and_sign_extends_low_byte() {
        let _lock = TEST_LOCK.lock();
        let vtable = crate::app::class_8900::Class6000VTable {
            slots_below: [None; 55],
            read: unreachable_read,
            read_typed: read_typed_result,
        };
        let mut store = Class6000 { vtable: &vtable };

        RAW_RESULT.store(0xffff_ff80, Ordering::Relaxed);
        assert_eq!(unsafe { class6000_property_6045_i8(&mut store) }, -128);
        assert_eq!(OBSERVED_KEY.load(Ordering::Relaxed), PROPERTY_KEY_6045);
        assert_eq!(OBSERVED_CLASS.load(Ordering::Relaxed), CLASS_ID_6000);
        assert_eq!(OBSERVED_KIND.load(Ordering::Relaxed), RESOURCE_KIND_23IU.0);

        RAW_RESULT.store(0x0000_007f, Ordering::Relaxed);
        assert_eq!(unsafe { class6000_property_6045_i8(&mut store) }, 127);
    }

    unsafe extern "C" fn unreachable_read(_store: *mut Class6000, _key: u32, _class_id: u32) -> u32 {
        unreachable!()
    }
}
