//! Destructor for the otherwise unidentified vtable `0x089a58c8` class.
//!
//! `vtable_089a58c8_destruct` — original: `FUN_083d20b4` @ `0x083d20b4`.
//!
//! **60 bytes**, `0x083d20b4..0x083d20ec`: 56 instruction bytes followed by
//! the vtable literal `0x089a58c8` at `0x083d20ec`; the next real function
//! starts at `0x083d20f0`. Decoding the raw ARM words finds **2 incoming plain
//! `bl` calls and 0 incoming predicated `bl` calls**. The body makes one plain
//! direct `bl` to `indexed_release`, one predicated virtual `blx` through the
//! payload vtable slot `+0x1c`, then tail-branches to `observable_array_destruct`.
//!
//! # Algorithm
//!
//! Install this class's vtable. If the target-width word at `+0x14` is nonzero,
//! invoke its vtable slot `+0x1c`; release the indexed elements in the base
//! prefix; then tail-chain to the observable-array destructor.
//!
//! Deliberate host-test deviations: the target's payload vtable and the
//! `indexed_release` object prefix both use target-width words, which cannot
//! represent native pointers on 64-bit hosts. Host tests replace those two
//! calls with seams; ARM calls the recovered target operations directly.

use super::observable_array::{observable_array_destruct, ObservableArray};

/// Literal installed by the destructor at `0x083d20ec`.
pub const VTABLE_089A58C8: u32 = 0x089a_58c8;

/// Observable-array base plus the two words touched by this destructor.
#[repr(C)]
pub struct Vtable089a58c8Object {
    pub array: ObservableArray,
    pub unknown_word_at_10: u32,
    pub payload: u32,
}

const _: [u8; 0x14] = [0; core::mem::offset_of!(Vtable089a58c8Object, payload)];
const _: [u8; 0x18] = [0; core::mem::size_of::<Vtable089a58c8Object>()];

type PayloadRelease = unsafe extern "C" fn(u32);
type IndexedRelease = unsafe extern "C" fn(*mut Vtable089a58c8Object);
#[cfg(target_arch = "arm")]
unsafe fn release_indexed_elements(this: *mut Vtable089a58c8Object) {
    crate::heap::indexed_release::indexed_release(this.cast());
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn indexed_release_unported(_this: *mut Vtable089a58c8Object) {}

/// Host-model seam for the direct `indexed_release` call at `0x083d20dc`.
#[cfg(not(target_arch = "arm"))]
pub static mut VTABLE_089A58C8_INDEXED_RELEASE: IndexedRelease = indexed_release_unported;

/// Host-model seam for the payload's target-vtable slot `+0x1c`.
#[cfg(not(target_arch = "arm"))]
pub static mut VTABLE_089A58C8_PAYLOAD_RELEASE: PayloadRelease = payload_release_unported;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn payload_release_unported(_payload: u32) {}

/// Destroys the observed derived observable-array object and returns `this`.
///
/// # Safety
///
/// `this` must reference a writable, target-layout [`Vtable089a58c8Object`].
/// A nonzero `payload` must satisfy its vtable release contract on ARM.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089a58c8_destruct(
    this: *mut Vtable089a58c8Object,
) -> *mut Vtable089a58c8Object {
    core::ptr::addr_of_mut!((*this).array.base.vtable).write_volatile(VTABLE_089A58C8);

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
            let release = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A58C8_PAYLOAD_RELEASE));
            release(payload);
        }
    }

    #[cfg(target_arch = "arm")]
    release_indexed_elements(this);
    #[cfg(not(target_arch = "arm"))]
    {
        let release = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_089A58C8_INDEXED_RELEASE));
        release(this);
    }
    observable_array_destruct(core::ptr::addr_of_mut!((*this).array)).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut PAYLOAD: u32 = 0;
    static mut INDEXED: usize = 0;
    static mut NOTIFY: usize = 0;

    unsafe extern "C" fn record_payload(payload: u32) {
        core::ptr::addr_of_mut!(PAYLOAD).write(payload);
    }

    unsafe extern "C" fn record_indexed(this: *mut Vtable089a58c8Object) {
        core::ptr::addr_of_mut!(INDEXED).write(this as usize);
    }

    unsafe extern "C" fn record_notify(this: *mut ObservableArray, _reason: u32) {
        core::ptr::addr_of_mut!(NOTIFY).write(this as usize);
    }

    struct SeamGuard {
        indexed: IndexedRelease,
        payload: PayloadRelease,
        notify: unsafe extern "C" fn(*mut ObservableArray, u32),
    }

    impl SeamGuard {
        unsafe fn install() -> Self {
            let indexed = core::ptr::addr_of!(VTABLE_089A58C8_INDEXED_RELEASE).read();
            let payload = core::ptr::addr_of!(VTABLE_089A58C8_PAYLOAD_RELEASE).read();
            let notify = core::ptr::addr_of!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).read();
            core::ptr::addr_of_mut!(VTABLE_089A58C8_INDEXED_RELEASE).write(record_indexed);
            core::ptr::addr_of_mut!(VTABLE_089A58C8_PAYLOAD_RELEASE).write(record_payload);
            core::ptr::addr_of_mut!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).write(record_notify);
            core::ptr::addr_of_mut!(PAYLOAD).write(0);
            core::ptr::addr_of_mut!(INDEXED).write(0);
            core::ptr::addr_of_mut!(NOTIFY).write(0);
            Self { indexed, payload, notify }
        }
    }

    impl Drop for SeamGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VTABLE_089A58C8_INDEXED_RELEASE).write(self.indexed);
                core::ptr::addr_of_mut!(VTABLE_089A58C8_PAYLOAD_RELEASE).write(self.payload);
                core::ptr::addr_of_mut!(super::super::observable_array::OBSERVABLE_ARRAY_NOTIFY).write(self.notify);
            }
        }
    }

    fn object(payload: u32) -> Vtable089a58c8Object {
        Vtable089a58c8Object {
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
    fn releases_payload_then_indexed_elements_then_array_base() {
        let _lock = LOCK.lock();
        let _guard = unsafe { SeamGuard::install() };
        let mut value = object(0x0801_2340);
        let this = core::ptr::addr_of_mut!(value);

        let returned = unsafe { vtable_089a58c8_destruct(this) };

        assert_eq!(returned, this);
        assert_eq!(unsafe { PAYLOAD }, 0x0801_2340);
        assert_eq!(unsafe { INDEXED }, this as usize);
        assert_eq!(unsafe { NOTIFY }, core::ptr::addr_of_mut!(value.array) as usize);
        assert_eq!(value.array.base.vtable, super::super::observable_array::OBSERVABLE_ARRAY_VTABLE);
        assert_eq!(value.array.len, 0);
        assert_eq!(value.array.storage, 0);
        assert_eq!(value.unknown_word_at_10, 0xa5a5_a5a5);
        assert_eq!(value.payload, 0x0801_2340);
    }

    #[test]
    fn null_payload_skips_virtual_release_but_runs_direct_and_base_cleanup() {
        let _lock = LOCK.lock();
        let _guard = unsafe { SeamGuard::install() };
        let mut value = object(0);
        let this = core::ptr::addr_of_mut!(value);

        unsafe { vtable_089a58c8_destruct(this) };

        assert_eq!(unsafe { PAYLOAD }, 0);
        assert_eq!(unsafe { INDEXED }, this as usize);
        assert_eq!(unsafe { NOTIFY }, core::ptr::addr_of_mut!(value.array) as usize);
    }
}
