//! `prid_checked_word_c0` — `FUN_0812b080` @ **0x0812b080**.
//!
//! # Raw extent and call sites
//!
//! The seven instructions through `pop {r4, pc}` at 0x0812b0ac are the full
//! **48-byte** extent: the separately linked `FUN_0812b0b0` begins at
//! 0x0812b0b0. Decoding every aligned ARM `B`/`BL` immediate in `osos.dec`
//! finds exactly **seven direct, unconditional `bl` call sites** at
//! 0x081289a0, 0x0812935c, 0x0812b1f8, 0x0812b2c8, 0x0812b300, 0x0812b4b4,
//! and 0x0812b4ec. There are no predicated calls or direct tail branches, and
//! no aligned data word targets this entry.
//!
//! # Algorithm
//!
//! If byte +0xda is zero, return the signed word at +0xc0. Otherwise fetch
//! the class-0x8900 singleton and read its first `("prID", 0x60f0)` resource
//! byte. Return +0xc0 only when that byte is one; every other signed byte,
//! including a missing resource (zero), returns the fixed value 37.
//!
//! # Deliberate deviations
//!
//! This function adds no dispatch seam: both direct ARM callees are existing
//! ports. It inherits `singleton_class_8900`'s documented crate-cache and
//! zeroing-constructor seam, so it is not hook-ready until `FUN_081ee0c0` can
//! construct the class-0x8900 resource store.

use crate::app::class_8900::Class8900;
use crate::app::class_8900_prid_first_byte::class_8900_prid_first_byte;
use crate::app::singletons::singleton_class_8900;

/// The receiver fields decoded by `FUN_0812b080`. Its concrete class is not
/// recovered; only the returned +0xc0 word and the +0xda prID gate are known.
#[repr(C)]
pub struct PridCheckedWordState {
    /// +0x00..+0xbc, not decoded by this port.
    pub state_below_word_c0: [u32; 48],
    /// +0xc0 — returned when the prID gate is clear or answers one.
    pub word_c0: i32,
    /// +0xc4..+0xd9, not decoded by this port.
    pub state_below_prid_gate: [u8; 0x16],
    /// +0xda — enables the class-0x8900 prID check when nonzero.
    pub prid_gate_enabled: u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0xc0] = [0; core::mem::offset_of!(PridCheckedWordState, word_c0)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0xda] = [0; core::mem::offset_of!(PridCheckedWordState, prid_gate_enabled)];

/// prid_checked_word_c0 — original: `FUN_0812b080` @ **0x0812b080**
/// (**48 bytes; seven unconditional `bl` call sites, binary-scanned**).
///
/// Returns `this->word_c0` unless `prid_gate_enabled` is nonzero and the
/// class-0x8900 `("prID", 0x60f0)` first byte is anything but one, in which
/// case it returns 37. Like the ARM implementation, `this` and the singleton
/// result are not NULL-guarded.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn prid_checked_word_c0(this: *const PridCheckedWordState) -> i32 {
    if (*this).prid_gate_enabled != 0 {
        let class_8900 = singleton_class_8900() as *const Class8900;
        if class_8900_prid_first_byte(class_8900) != 1 {
            return 37;
        }
    }
    (*this).word_c0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::class_8900::{Class6000, Class6000VTable};
    use crate::app::resource_chain::{ResourceKind, ResourceProvider, ResourceProviderVTable};
    use crate::app::singletons::{CLASS_8900_INSTANCE, SINGLETON_LOCK};
    use core::ptr;

    static mut ANSWER: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn find_prid(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        found: *mut *mut u8,
    ) -> u32 {
        if ANSWER.is_null() {
            0
        } else {
            *found = ANSWER;
            1
        }
    }

    unsafe extern "C" fn read_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
    ) -> u32 {
        0
    }

    unsafe extern "C" fn replacement_permits(
        _provider: *mut ResourceProvider,
        _replacement: *mut ResourceProvider,
    ) -> u32 {
        1
    }

    unsafe extern "C" fn write_not_called(
        _provider: *mut ResourceProvider,
        _kind: ResourceKind,
        _id: u32,
        _value: u32,
        _flags: u32,
    ) -> u32 {
        0
    }

    const VTABLE: ResourceProviderVTable = ResourceProviderVTable {
        slots_below: [None; 22],
        read: read_not_called,
        slot_5c: None,
        replacement_allowed: replacement_permits,
        find: find_prid,
        write: write_not_called,
    };

    #[repr(C)]
    struct ResourceBackedClass6000 {
        class: Class6000,
        state_below_next: [*mut u8; 4],
        next: *mut ResourceProvider,
    }

    fn state(word_c0: i32, prid_gate_enabled: u8) -> PridCheckedWordState {
        PridCheckedWordState {
            state_below_word_c0: [0; 48],
            word_c0,
            state_below_prid_gate: [0; 0x16],
            prid_gate_enabled,
        }
    }

    #[test]
    fn returns_word_when_prid_gate_is_clear() {
        let _guard = SINGLETON_LOCK.lock();
        let receiver = state(-23, 0);

        // No class-0x8900 fixture is installed: a call through the gate would
        // reach the singleton's null store and fault, as the ARM does.
        assert_eq!(unsafe { prid_checked_word_c0(&receiver) }, -23);
    }

    #[test]
    fn enabled_gate_accepts_only_prid_byte_one() {
        let _guard = SINGLETON_LOCK.lock();
        let mut provider = ResourceBackedClass6000 {
            class: Class6000 {
                vtable: &VTABLE as *const _ as *const Class6000VTable,
            },
            state_below_next: [ptr::null_mut(); 4],
            next: ptr::null_mut(),
        };
        let mut class_8900 = Class8900 {
            state_below_cache: [0; 12],
            cached_6031: 0,
            state_below_store: [0; 209],
            store: &mut provider.class,
        };
        let receiver = state(0x1234, 1);
        let mut one = 1_u8;
        let mut zero = 0_u8;
        let mut negative_one = 0xff_u8;

        let results = unsafe {
            let previous_instance = CLASS_8900_INSTANCE;
            CLASS_8900_INSTANCE = (&mut class_8900 as *mut Class8900).cast();

            ANSWER = &mut one;
            let accepted = prid_checked_word_c0(&receiver);
            ANSWER = &mut zero;
            let missing = prid_checked_word_c0(&receiver);
            ANSWER = &mut negative_one;
            let negative = prid_checked_word_c0(&receiver);

            ANSWER = ptr::null_mut();
            CLASS_8900_INSTANCE = previous_instance;
            (accepted, missing, negative)
        };

        assert_eq!(results, (0x1234, 37, 37));
    }
}
