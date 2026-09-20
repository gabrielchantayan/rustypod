//! Destructor for the otherwise unidentified vtable `0x089a5718` class.
//!
//! `vtable_089a5718_destruct` — original: `FUN_083d1f04` @ `0x083d1f04`.
//!
//! **56 bytes**, `0x083d1f04..0x083d1f3c`: 52 instruction bytes followed by
//! the vtable literal `0x089a5718` at `0x083d1f3c`; the next real function
//! starts at `0x083d1f40`. Decoding every ARM immediate branch in `osos.dec`
//! finds **3 plain `bl` callers** (0x0826b748, 0x083d1d74, 0x083d1dc0) and
//! **0 predicated `bl` callers**. The body has one direct `bl`, one predicated
//! `blx` through the payload's vtable, and tail-branches to
//! `observable_array_destruct`.
//!
//! # Algorithm
//!
//! Install this class's vtable, then, if the target-width word at `+0x14` is
//! nonzero, invoke its vtable slot `+0x1c`. Run the direct but still-unported
//! `0x083d1e30` base cleanup, then tail-chain to the ported observable-array
//! destructor. The class identity and the slot's semantic identity are not
//! established, so their names deliberately state only their observed roles.
//!
//! Deliberate host-test deviations: target virtual dispatch reads a target
//! vtable function pointer at `payload->vtable + 0x1c`, and the base-cleanup
//! seam calls its fixed `0x083d1e30` address. Host tests replace both with
//! seams because native function pointers do not fit in that target-width
//! word layout and cannot call firmware addresses.

use super::observable_array::{observable_array_destruct, ObservableArray};

/// Literal installed by the destructor at `0x083d1f3c`.
pub const VTABLE_089A5718: u32 = 0x089a_5718;

/// Observable-array base plus the only two derived words touched here.
#[repr(C)]
pub struct Vtable089a5718Object {
    pub array: ObservableArray,
    pub unknown_word_at_10: u32,
    pub payload: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(Vtable089a5718Object, payload)];
const _: [u8; 0x18] = [0; core::mem::size_of::<Vtable089a5718Object>()];

type PayloadRelease = unsafe extern "C" fn(u32);
type BaseCleanup = unsafe extern "C" fn(*mut Vtable089a5718Object);

/// Direct-call seam for unported `FUN_083d1e30` @ `0x083d1e30`.
pub static mut VTABLE_089A5718_BASE_CLEANUP: BaseCleanup = vtable_089a5718_base_cleanup_unported;

#[cfg(target_arch = "arm")]
unsafe extern "C" fn vtable_089a5718_base_cleanup_unported(this: *mut Vtable089a5718Object) {
    let cleanup: BaseCleanup = core::mem::transmute(0x083d_1e30usize);
    cleanup(this);
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn vtable_089a5718_base_cleanup_unported(_this: *mut Vtable089a5718Object) {}

/// Host-model seam for the payload's target-vtable slot `+0x1c`.
#[cfg(not(target_arch = "arm"))]
pub static mut VTABLE_089A5718_PAYLOAD_RELEASE: PayloadRelease = vtable_089a5718_payload_release_unported;

unsafe extern "C" fn vtable_089a5718_payload_release_unported(_payload: u32) {}

/// Destroys the observed derived observable-array object and returns `this`.
///
/// # Safety
///
/// `this` must reference a writable, target-layout [`Vtable089a5718Object`].
/// A nonzero `payload` must satisfy its vtable release contract on ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089a5718_destruct(
    this: *mut Vtable089a5718Object,
) -> *mut Vtable089a5718Object {
    core::ptr::addr_of_mut!((*this).array.base.vtable).write_volatile(VTABLE_089A5718);

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
            let release = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A5718_PAYLOAD_RELEASE));
            release(payload);
        }
    }

    let base_cleanup = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A5718_BASE_CLEANUP));
    base_cleanup(this);
    observable_array_destruct(core::ptr::addr_of_mut!((*this).array)).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PAYLOAD: u32 = 0;
    static mut BASE: usize = 0;
    static mut NOTIFY: usize = 0;

    unsafe extern "C" fn record_payload(payload: u32) {
        core::ptr::addr_of_mut!(PAYLOAD).write(payload);
    }

    unsafe extern "C" fn record_base(this: *mut Vtable089a5718Object) {
        core::ptr::addr_of_mut!(BASE).write(this as usize);
    }

    unsafe extern "C" fn record_notify(this: *mut ObservableArray, _reason: u32) {
        core::ptr::addr_of_mut!(NOTIFY).write(this as usize);
    }

    struct SeamGuard {
        base: BaseCleanup,
        payload: PayloadRelease,
        notify: unsafe extern "C" fn(*mut ObservableArray, u32),
    }

    impl SeamGuard {
        unsafe fn install() -> Self {
            let base = core::ptr::addr_of!(VTABLE_089A5718_BASE_CLEANUP).read();
            let payload = core::ptr::addr_of!(VTABLE_089A5718_PAYLOAD_RELEASE).read();
            let notify = core::ptr::addr_of!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).read();
            core::ptr::addr_of_mut!(VTABLE_089A5718_BASE_CLEANUP).write(record_base);
            core::ptr::addr_of_mut!(VTABLE_089A5718_PAYLOAD_RELEASE).write(record_payload);
            core::ptr::addr_of_mut!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).write(record_notify);
            core::ptr::addr_of_mut!(PAYLOAD).write(0);
            core::ptr::addr_of_mut!(BASE).write(0);
            core::ptr::addr_of_mut!(NOTIFY).write(0);
            Self { base, payload, notify }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VTABLE_089A5718_BASE_CLEANUP).write(self.base);
                core::ptr::addr_of_mut!(VTABLE_089A5718_PAYLOAD_RELEASE).write(self.payload);
                core::ptr::addr_of_mut!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).write(self.notify);
            }
        }
    }

    fn object(payload: u32) -> Vtable089a5718Object {
        Vtable089a5718Object {
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
    fn releases_nonnull_payload_then_cleans_base_and_destructs_array() {
        let _lock = LOCK.lock();
        let _guard = unsafe { SeamGuard::install() };
        let mut value = object(0x0801_2340);
        let this = core::ptr::addr_of_mut!(value);

        let returned = unsafe { vtable_089a5718_destruct(this) };

        assert_eq!(returned, this);
        assert_eq!(unsafe { PAYLOAD }, 0x0801_2340);
        assert_eq!(unsafe { BASE }, this as usize);
        assert_eq!(unsafe { NOTIFY }, core::ptr::addr_of_mut!(value.array) as usize);
        assert_eq!(value.array.base.vtable, super::super::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(value.array.len, 0);
        assert_eq!(value.array.storage, 0);
        assert_eq!(value.unknown_word_at_10, 0xa5a5_a5a5);
        assert_eq!(value.payload, 0x0801_2340);
    }

    #[test]
    fn null_payload_skips_virtual_release_but_runs_both_base_teardowns() {
        let _lock = LOCK.lock();
        let _guard = unsafe { SeamGuard::install() };
        let mut value = object(0);
        let this = core::ptr::addr_of_mut!(value);

        unsafe { vtable_089a5718_destruct(this) };

        assert_eq!(unsafe { PAYLOAD }, 0);
        assert_eq!(unsafe { BASE }, this as usize);
        assert_eq!(unsafe { NOTIFY }, core::ptr::addr_of_mut!(value.array) as usize);
    }
}
