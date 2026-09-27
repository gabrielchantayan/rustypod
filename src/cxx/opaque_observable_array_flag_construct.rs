//! `opaque_observable_array_flag_construct` — original: `FUN_083d0ac8` @
//! 0x083d0ac8 (40 bytes: 36 bytes of code plus the 4-byte literal
//! 0x089a4638 at 0x083d0aec).
//!
//! # Extent and reachability, binary-verified
//!
//! The nine ARM instructions span 0x083d0ac8..0x083d0ae8. The `ldr r1,
//! [pc,#0x10]` at 0x083d0ad4 reads the literal at 0x083d0aec; the next
//! independently entered function begins at 0x083d0af0. Whole-image decoding
//! finds three inbound plain unconditional `bl` instructions (0x08291e9c,
//! 0x08291ebc, and 0x08291f3c), and no predicated direct `bl` callers. The
//! body makes one plain direct `bl`, to the ported `observable_array_construct`
//! @ 0x08271cec; it has no predicated direct call.
//!
//! # Algorithm
//!
//! Construct the 16-byte `ObservableArray` base, overwrite its vtable with the
//! literal, copy the incoming byte to +0x10, and clear the word at +0x14. The
//! literal has no verified class identity, so this module deliberately uses an
//! opaque role name rather than inventing one. Deliberate deviations: none.
//!
//! - `opaque_observable_array_flag_destruct` — original: `FUN_083d0af0` @
//!   0x083d0af0 (**60 bytes**: 56 bytes of instructions plus the literal
//!   0x089a4638 @ 0x083d0b28). The next independently entered function starts
//!   with `push {r4,r5,r6,lr}` at 0x083d0b2c. Whole-image A32 decoding finds
//!   two inbound plain `bl` sites (0x0826b568 and 0x08291fbc), no predicated
//!   direct `bl` callers. The body has one plain direct `bl` to
//!   `FUN_083d0a20`, one predicated virtual `blxne` through the word at
//!   `allocation->vtable + 0x1c`, and tail-branches to
//!   [`observable_array_destruct`] @ 0x08271d2c.
//!
//!   It reinstalls this class's vtable, conditionally dispatches virtual slot
//!   +0x1c on the opaque word at +0x14, then destroys the observable-array
//!   base. The virtual target has no verified identity, so it remains named
//!   for its observed slot and argument. Deliberate deviation: Rust models
//!   the tail branch as a direct call and uses a host seam for the target-only
//!   32-bit virtual dispatch; field writes and call order are preserved.

use core::ptr;

use super::observable_array::observable_array_destruct;
use super::opaque_observable_array_auxiliary_destroy::opaque_observable_array_auxiliary_destroy;

/// Target default for the opaque virtual release at `allocation->vtable + 0x1c`.
#[cfg(target_os = "none")]
unsafe fn opaque_observable_array_flag_release_word_at_14(allocation: *mut u8) {
    let vtable = allocation.cast::<u32>().read_volatile() as *const u32;
    let release: unsafe extern "C" fn(*mut u8) = core::mem::transmute(vtable.add(0x1c / 4).read_volatile());
    release(allocation);
}

/// Host default for the unported virtual target.
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_opaque_observable_array_flag_release_word_at_14(_allocation: *mut u8) {}

/// Host seam for the unported virtual target at target vtable slot `+0x1c`.
#[cfg(not(target_os = "none"))]
pub static mut OPAQUE_OBSERVABLE_ARRAY_FLAG_RELEASE_WORD_AT_14: unsafe extern "C" fn(*mut u8) =
    missing_opaque_observable_array_flag_release_word_at_14;


use super::observable_array::{observable_array_construct, ObservableArray, OBSERVABLE_ARRAY_SIZE};

/// Literal installed by the ARM constructor at offset +0x00.
pub const OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE: u32 = 0x089a_4638;

/// Target layout initialized by [`opaque_observable_array_flag_construct`].
#[repr(C)]
pub struct OpaqueObservableArrayFlag {
    pub array: ObservableArray,
    pub flag_at_10: u8,
    pub padding_11_13: [u8; 3],
    pub word_at_14: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(OpaqueObservableArrayFlag, array)];
const _: [u8; OBSERVABLE_ARRAY_SIZE] = [0; core::mem::offset_of!(OpaqueObservableArrayFlag, flag_at_10)];
const _: [u8; 0x14] = [0; core::mem::offset_of!(OpaqueObservableArrayFlag, word_at_14)];
const _: [u8; 0x18] = [0; core::mem::size_of::<OpaqueObservableArrayFlag>()];

/// Constructs the observed opaque observable-array object and returns `this`.
///
/// # Safety
///
/// `this` must point to at least 24 writable, word-aligned bytes. The stock
/// constructor has no NULL or alignment guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_observable_array_flag_construct")]
pub unsafe extern "C" fn opaque_observable_array_flag_construct(
    this: *mut OpaqueObservableArrayFlag,
    flag: u8,
) -> *mut OpaqueObservableArrayFlag {
    let object = unsafe { observable_array_construct(core::ptr::addr_of_mut!((*this).array)) }
        .cast::<OpaqueObservableArrayFlag>();

    unsafe {
        core::ptr::addr_of_mut!((*object).array.base.vtable)
            .write_volatile(OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE);
        core::ptr::addr_of_mut!((*object).flag_at_10).write_volatile(flag);
        core::ptr::addr_of_mut!((*object).word_at_14).write_volatile(0);
    }
    object
}

/// Destroys the opaque observable-array object after releasing its auxiliary word.
///
/// # Safety
///
/// `this` must point to a live [`OpaqueObservableArrayFlag`]. When `word_at_14`
/// is nonzero, it must be an allocation whose first word is a vtable with a
/// callable target-word slot at `+0x1c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.opaque_observable_array_flag_destruct")]
pub unsafe extern "C" fn opaque_observable_array_flag_destruct(
    this: *mut OpaqueObservableArrayFlag,
) -> *mut OpaqueObservableArrayFlag {
    unsafe {
        ptr::addr_of_mut!((*this).array.base.vtable)
            .write_volatile(OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE);
        let allocation = ptr::addr_of!((*this).word_at_14).read_volatile() as usize as *mut u8;
        if !allocation.is_null() {
            #[cfg(target_os = "none")]
            opaque_observable_array_flag_release_word_at_14(allocation);
            #[cfg(not(target_os = "none"))]
            ptr::read_volatile(ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_FLAG_RELEASE_WORD_AT_14))(allocation);
        }
        opaque_observable_array_auxiliary_destroy(this.cast());
        observable_array_destruct(ptr::addr_of_mut!((*this).array));
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;
    use crate::app::indexed_virtual_value::{IndexedVirtualValueOps, INDEXED_VIRTUAL_VALUE_OPS};

    static RELEASE_LOCK: Mutex<()> = Mutex::new(());
    static RELEASE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
    static ZERO_INDEXED_VALUE: u32 = 0;


    unsafe extern "C" fn record_release(allocation: *mut u8) {
        RELEASE_CALLS.fetch_add(1, Ordering::SeqCst);
        RELEASED_ALLOCATION.store(allocation as usize, Ordering::SeqCst);
    }

    unsafe extern "C" fn zero_indexed_value(_: *mut u8, _: i32) -> *const u32 {
        &ZERO_INDEXED_VALUE
    }

    struct ReleaseReset {
        release: unsafe extern "C" fn(*mut u8),
        indexed_value: IndexedVirtualValueOps,
    }

    impl Drop for ReleaseReset {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(OPAQUE_OBSERVABLE_ARRAY_FLAG_RELEASE_WORD_AT_14)
                    .write_volatile(self.release);
                ptr::addr_of_mut!(INDEXED_VIRTUAL_VALUE_OPS)
                    .write_volatile(ptr::read_volatile(ptr::addr_of!(self.indexed_value)));
            }
        }
    }

    fn install_release() -> ReleaseReset {
        unsafe {
            let reset = ReleaseReset {
                release: ptr::addr_of!(OPAQUE_OBSERVABLE_ARRAY_FLAG_RELEASE_WORD_AT_14).read_volatile(),
                indexed_value: ptr::addr_of!(INDEXED_VIRTUAL_VALUE_OPS).read_volatile(),
            };
            ptr::addr_of_mut!(OPAQUE_OBSERVABLE_ARRAY_FLAG_RELEASE_WORD_AT_14).write_volatile(record_release);
            ptr::addr_of_mut!(INDEXED_VIRTUAL_VALUE_OPS).write_volatile(IndexedVirtualValueOps {
                value_at: zero_indexed_value,
            });
            RELEASE_CALLS.store(0, Ordering::SeqCst);
            RELEASED_ALLOCATION.store(0, Ordering::SeqCst);
            reset
        }
    }
    use crate::cxx::observable_array::FrameworkObject;

    #[repr(C)]
    struct Fixture {
        object: OpaqueObservableArrayFlag,
        trailing: u32,
    }

    #[test]
    fn constructs_base_preserves_each_flag_value_and_clears_only_word_at_14() {
        for flag in [0, 1, u8::MAX] {
            let mut fixture = Fixture {
                object: OpaqueObservableArrayFlag {
                    array: ObservableArray {
                        base: FrameworkObject { vtable: 0xdead_beef },
                        len: u32::MAX,
                        storage: 0x1111_1111,
                        observers: 0x2222_2222,
                    },
                    flag_at_10: !flag,
                    padding_11_13: [0xa5; 3],
                    word_at_14: u32::MAX,
                },
                trailing: 0xcafe_babe,
            };
            let object = core::ptr::addr_of_mut!(fixture.object);

            let returned = unsafe { opaque_observable_array_flag_construct(object, flag) };

            assert_eq!(returned, object);
            assert_eq!(fixture.object.array.base.vtable, OPAQUE_OBSERVABLE_ARRAY_FLAG_VTABLE);
            assert_eq!(fixture.object.array.len, 0);
            assert_eq!(fixture.object.array.storage, 0);
            assert_eq!(fixture.object.array.observers, 0);
            assert_eq!(fixture.object.flag_at_10, flag);
            assert_eq!(fixture.object.padding_11_13, [0xa5; 3]);
            assert_eq!(fixture.object.word_at_14, 0);
            assert_eq!(fixture.trailing, 0xcafe_babe);
        }
    }

    #[test]
    fn destruct_releases_nonzero_auxiliary_word_before_destroying_base() {
        let _lock = RELEASE_LOCK.lock();
        let _reset = install_release();
        let mut fixture = Fixture {
            object: OpaqueObservableArrayFlag {
                array: ObservableArray {
                    base: FrameworkObject { vtable: 0xdead_beef },
                    len: 7,
                    storage: 0,
                    observers: 0,
                },
                flag_at_10: 0x7a,
                padding_11_13: [0xa5; 3],
                word_at_14: 0x1234_5000,
            },
            trailing: 0xcafe_babe,
        };

        let returned = unsafe { opaque_observable_array_flag_destruct(ptr::addr_of_mut!(fixture.object)) };

        assert_eq!(returned, ptr::addr_of_mut!(fixture.object));
        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(RELEASED_ALLOCATION.load(Ordering::SeqCst), 0x1234_5000);
        assert_eq!(fixture.object.array.base.vtable, crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(fixture.object.array.len, 0);
        assert_eq!(fixture.object.word_at_14, 0x1234_5000, "the retail destructor does not clear this field");
        assert_eq!(fixture.object.flag_at_10, 0x7a);
        assert_eq!(fixture.object.padding_11_13, [0xa5; 3]);
        assert_eq!(fixture.trailing, 0xcafe_babe);
    }

    #[test]
    fn destruct_skips_null_auxiliary_word() {
        let _lock = RELEASE_LOCK.lock();
        let _reset = install_release();
        let mut fixture = Fixture {
            object: OpaqueObservableArrayFlag {
                array: ObservableArray {
                    base: FrameworkObject { vtable: 0 },
                    len: 0,
                    storage: 0,
                    observers: 0,
                },
                flag_at_10: 0,
                padding_11_13: [0xa5; 3],
                word_at_14: 0,
            },
            trailing: 0xcafe_babe,
        };

        unsafe { opaque_observable_array_flag_destruct(ptr::addr_of_mut!(fixture.object)); }

        assert_eq!(RELEASE_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.object.array.base.vtable, crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(fixture.trailing, 0xcafe_babe);
    }
}
