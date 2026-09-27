//! Destructor for the otherwise unidentified vtable `0x089a38b8` class.
//!
//! `vtable_089a38b8_destruct` — retailOS `FUN_083cfbb8` @ `0x083cfbb8`.
//!
//! **60 bytes**, `0x083cfbb8..0x083cfbec`: 56 ARM instruction bytes plus the
//! vtable literal `0x089a38b8` at `0x083cfbf0`; the next real function starts
//! at `0x083cfbf4`. Raw-word decoding finds **2 inbound plain `bl` callers**
//! and **0 inbound predicated `bl` callers**. The body has one direct `bl`, one
//! predicated `blx` through the payload's vtable, and tail-branches to
//! `observable_array_destruct`.
//!
//! # Algorithm
//!
//! Installs this class's vtable, conditionally invokes the target-width
//! payload word at `+0x14` through vtable slot `+0x1c`, runs the direct but
//! unported `FUN_083cfaf8` base cleanup, then tail-chains to the ported
//! observable-array destructor. The class, payload, slot, and base-cleanup
//! identities remain unestablished; their names state only observed roles.
//!
//! Deliberate host-test deviations: native function pointers cannot fit in the
//! target's `u32` vtable layout and firmware address `0x083cfaf8` is not
//! executable on the host, so tests replace both operations through seams.

use super::observable_array::{observable_array_destruct, ObservableArray};

/// Literal installed by the destructor at `0x083cfbf0`.
pub const VTABLE_089A38B8: u32 = 0x089a_38b8;

/// Observable-array base plus the only two derived words touched here.
#[repr(C)]
pub struct Vtable089a38b8Object {
    pub array: ObservableArray,
    pub unknown_word_at_10: u32,
    pub payload: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(Vtable089a38b8Object, payload)];
const _: [u8; 0x18] = [0; core::mem::size_of::<Vtable089a38b8Object>()];

type PayloadRelease = unsafe extern "C" fn(u32);
type BaseCleanup = unsafe extern "C" fn(*mut Vtable089a38b8Object);

/// Direct-call seam for unported `FUN_083cfaf8` @ `0x083cfaf8`.
pub static mut VTABLE_089A38B8_BASE_CLEANUP: BaseCleanup = vtable_089a38b8_base_cleanup_unported;

#[cfg(target_arch = "arm")]
unsafe extern "C" fn vtable_089a38b8_base_cleanup_unported(this: *mut Vtable089a38b8Object) {
    let cleanup: BaseCleanup = core::mem::transmute(0x083c_faf8usize);
    cleanup(this);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn vtable_089a38b8_base_cleanup_unported(_this: *mut Vtable089a38b8Object) {}

/// Host-model seam for the payload's target-vtable slot `+0x1c`.
#[cfg(not(target_arch = "arm"))]
pub static mut VTABLE_089A38B8_PAYLOAD_RELEASE: PayloadRelease = vtable_089a38b8_payload_release_unported;

unsafe extern "C" fn vtable_089a38b8_payload_release_unported(_payload: u32) {}

/// Destroys the observed derived observable-array object and returns `this`.
///
/// # Safety
///
/// `this` must reference a writable, target-layout [`Vtable089a38b8Object`].
/// A nonzero `payload` must satisfy its vtable release contract on ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089a38b8_destruct(
    this: *mut Vtable089a38b8Object,
) -> *mut Vtable089a38b8Object {
    core::ptr::addr_of_mut!((*this).array.base.vtable).write_volatile(VTABLE_089A38B8);

    let payload = core::ptr::addr_of!((*this).payload).read_volatile();
    if payload != 0 {
        #[cfg(target_arch = "arm")]
        {
            let vtable = core::ptr::read_volatile(payload as *const u32);
            let release: PayloadRelease = core::mem::transmute(core::ptr::read_volatile(
                (vtable as *const u32).add(0x1c / 4),
            ));
            release(payload);
        }
        #[cfg(not(target_arch = "arm"))]
        {
            let release = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A38B8_PAYLOAD_RELEASE));
            release(payload);
        }
    }

    let base_cleanup = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A38B8_BASE_CLEANUP));
    base_cleanup(this);
    observable_array_destruct(core::ptr::addr_of_mut!((*this).array)).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut EVENTS: [u8; 3] = [0; 3];
    static mut EVENT_COUNT: usize = 0;
    static mut PAYLOAD: u32 = 0;
    static mut BASE: usize = 0;

    unsafe fn record(event: u8) {
        core::ptr::addr_of_mut!(EVENTS).cast::<u8>().add(EVENT_COUNT).write(event);
        EVENT_COUNT += 1;
    }

    unsafe extern "C" fn record_payload(payload: u32) {
        PAYLOAD = payload;
        record(1);
    }

    unsafe extern "C" fn record_base(this: *mut Vtable089a38b8Object) {
        BASE = this as usize;
        record(2);
    }

    unsafe extern "C" fn record_notify(_: *mut ObservableArray, _: u32) {
        record(3);
    }

    struct SeamGuard {
        base: BaseCleanup,
        payload: PayloadRelease,
        notify: unsafe extern "C" fn(*mut ObservableArray, u32),
    }

    impl SeamGuard {
        unsafe fn install() -> Self {
            let base = core::ptr::addr_of!(VTABLE_089A38B8_BASE_CLEANUP).read();
            let payload = core::ptr::addr_of!(VTABLE_089A38B8_PAYLOAD_RELEASE).read();
            let notify = core::ptr::addr_of!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).read();
            core::ptr::addr_of_mut!(VTABLE_089A38B8_BASE_CLEANUP).write(record_base);
            core::ptr::addr_of_mut!(VTABLE_089A38B8_PAYLOAD_RELEASE).write(record_payload);
            core::ptr::addr_of_mut!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).write(record_notify);
            EVENTS = [0; 3]; EVENT_COUNT = 0; PAYLOAD = 0; BASE = 0;
            Self { base, payload, notify }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VTABLE_089A38B8_BASE_CLEANUP).write(self.base);
                core::ptr::addr_of_mut!(VTABLE_089A38B8_PAYLOAD_RELEASE).write(self.payload);
                core::ptr::addr_of_mut!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).write(self.notify);
            }
        }
    }

    fn object(payload: u32) -> Vtable089a38b8Object {
        Vtable089a38b8Object {
            array: ObservableArray {
                base: super::super::observable_array::FrameworkObject { vtable: 0xdead_beef },
                len: 4,
                storage: 0,
                observers: 0,
            },
            unknown_word_at_10: 0xa5a5_a5a5,
            payload,
        }
    }

    #[test]
    fn releases_nonnull_payload_before_base_and_array_cleanup() {
        let _lock = LOCK.lock();
        let _guard = unsafe { SeamGuard::install() };
        let mut value = object(0x0801_2340);
        let this = core::ptr::addr_of_mut!(value);

        let returned = unsafe { vtable_089a38b8_destruct(this) };

        assert_eq!(returned, this);
        assert_eq!(unsafe { PAYLOAD }, 0x0801_2340);
        assert_eq!(unsafe { BASE }, this as usize);
        assert_eq!(unsafe { EVENTS }, [1, 2, 3]);
        assert_eq!(value.array.base.vtable, super::super::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(value.array.len, 0);
        assert_eq!(value.array.storage, 0);
        assert_eq!(value.unknown_word_at_10, 0xa5a5_a5a5);
        assert_eq!(value.payload, 0x0801_2340);
    }

    #[test]
    fn skips_null_payload_release() {
        let _lock = LOCK.lock();
        let _guard = unsafe { SeamGuard::install() };
        let mut value = object(0);

        unsafe { vtable_089a38b8_destruct(core::ptr::addr_of_mut!(value)) };

        assert_eq!(unsafe { PAYLOAD }, 0);
        assert_eq!(unsafe { EVENTS }, [2, 3, 0]);
    }
}
