//! `refcounted_owner_callback_dispatch` — original: `FUN_08133cc0` @
//! **0x08133cc0** (**96 bytes**, exactly `0x08133cc0..0x08133d20`; the next
//! separately linked function begins at `0x08133d20`).
//!
//! # Algorithm
//!
//! Dereferences the refcounted-body handle at `owner+0x28`, then invokes the
//! recovered callback object's vtable slots `+0xdc`, `+0x13c`, and `+0x44` in
//! that order. The slots receive `(object)`, `(output, object, selector)`, and
//! `(object, output)` respectively; the last is tail-dispatched by retailOS.
//! Raw `osos.dec` decoding finds five direct inbound `bl` sites, all plain and
//! unconditional (`0x081310e0`, `0x081311b8`, `0x08131354`, `0x08131458`, and
//! `0x08131498`), with zero predicated direct `bl` forms.
//!
//! # Deliberate deviations
//!
//! The target tail `bx` is an ordinary final Rust call. Host vtable function
//! pointers are native-width while target slots remain four-byte words; target
//! offset assertions preserve the recovered layout. The virtual slot identities
//! are unestablished, so names describe only their observed dispatch roles.

use crate::cxx::handle::{handle_deref_or_null, RefcountedBodyOwner};

const FINALIZE_SLOT_INDEX: usize = 0x44 / 4;
const INITIALIZE_SLOT_INDEX: usize = 0xdc / 4;
const CONSTRUCT_SLOT_INDEX: usize = 0x13c / 4;

/// Callback object reached through an owner's refcounted handle.
#[repr(C)]
pub struct RefcountedOwnerCallback {
    pub vtable: *const RefcountedOwnerCallbackVtable,
}

/// Recovered slots of [`RefcountedOwnerCallback`]'s vtable.
#[repr(C)]
pub struct RefcountedOwnerCallbackVtable {
    pub unresolved_00_40: [usize; FINALIZE_SLOT_INDEX],
    /// `+0x44`: completes the callback sequence.
    pub finalize: unsafe extern "C" fn(*mut RefcountedOwnerCallback, *mut u8),
    pub unresolved_48_d8: [usize; INITIALIZE_SLOT_INDEX - FINALIZE_SLOT_INDEX - 1],
    /// `+0xdc`: initializes the callback object.
    pub initialize: unsafe extern "C" fn(*mut RefcountedOwnerCallback),
    pub unresolved_e0_138: [usize; CONSTRUCT_SLOT_INDEX - INITIALIZE_SLOT_INDEX - 1],
    /// `+0x13c`: populates the caller-supplied output.
    pub construct: unsafe extern "C" fn(*mut u8, *mut RefcountedOwnerCallback, u32),
}

#[cfg(target_os = "none")]
const _: [u8; 0x44] = [0; core::mem::offset_of!(RefcountedOwnerCallbackVtable, finalize)];
#[cfg(target_os = "none")]
const _: [u8; 0xdc] = [0; core::mem::offset_of!(RefcountedOwnerCallbackVtable, initialize)];
#[cfg(target_os = "none")]
const _: [u8; 0x13c] = [0; core::mem::offset_of!(RefcountedOwnerCallbackVtable, construct)];

/// Resolves `owner.body` afresh, as each of the three retailOS calls does.
///
/// The volatile load prevents LLVM from merging the independently observable
/// handle dereferences across a callback which can mutate the owner or body.
#[inline(always)]
unsafe fn callback_from_owner(owner: *const RefcountedBodyOwner) -> *mut RefcountedOwnerCallback {
    let body = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*owner).body)) };
    let slot: *const *mut u8 = body.cast();
    unsafe { handle_deref_or_null(&slot).cast() }
}

/// Dispatches the three recovered callback slots through `owner.body`.
///
/// # Safety
///
/// `owner` must point to a readable [`RefcountedBodyOwner`] whose body handle
/// resolves to a readable callback object. Its vtable and the three recovered
/// slots must be callable with the decoded arguments; `output` is passed
/// through unchanged and must meet the slots' requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn refcounted_owner_callback_dispatch(
    output: *mut u8,
    owner: *const RefcountedBodyOwner,
    selector: u32,
) {
    let callback = unsafe { callback_from_owner(owner) };
    let vtable = unsafe { (*callback).vtable };
    unsafe { ((*vtable).initialize)(callback) };

    let callback = unsafe { callback_from_owner(owner) };
    let vtable = unsafe { (*callback).vtable };
    unsafe { ((*vtable).construct)(output, callback, selector) };

    let callback = unsafe { callback_from_owner(owner) };
    let vtable = unsafe { (*callback).vtable };
    unsafe { ((*vtable).finalize)(callback, output) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::handle::RefcountedBody;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static CALLBACK: AtomicUsize = AtomicUsize::new(0);
    static OUTPUT: AtomicUsize = AtomicUsize::new(0);
    static SELECTOR: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn initialize(callback: *mut RefcountedOwnerCallback) {
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(callback as usize, CALLBACK.load(Ordering::SeqCst));
    }

    unsafe extern "C" fn construct(
        output: *mut u8,
        callback: *mut RefcountedOwnerCallback,
        selector: u32,
    ) {
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 1);
        assert_eq!(callback as usize, CALLBACK.load(Ordering::SeqCst));
        assert_eq!(output as usize, OUTPUT.load(Ordering::SeqCst));
        assert_eq!(selector as usize, SELECTOR.load(Ordering::SeqCst));
    }

    unsafe extern "C" fn finalize(callback: *mut RefcountedOwnerCallback, output: *mut u8) {
        assert_eq!(CALLS.fetch_add(1, Ordering::SeqCst), 2);
        assert_eq!(callback as usize, CALLBACK.load(Ordering::SeqCst));
        assert_eq!(output as usize, OUTPUT.load(Ordering::SeqCst));
    }

    #[test]
    fn dispatches_recovered_slots_with_exact_arguments() {
        let vtable = RefcountedOwnerCallbackVtable {
            unresolved_00_40: [0; FINALIZE_SLOT_INDEX],
            finalize,
            unresolved_48_d8: [0; INITIALIZE_SLOT_INDEX - FINALIZE_SLOT_INDEX - 1],
            initialize,
            unresolved_e0_138: [0; CONSTRUCT_SLOT_INDEX - INITIALIZE_SLOT_INDEX - 1],
            construct,
        };
        let mut callback = RefcountedOwnerCallback { vtable: &vtable };
        let mut body = RefcountedBody {
            opaque0: (&mut callback as *mut RefcountedOwnerCallback) as usize,
            refcount: 1,
            mutex: core::ptr::null_mut(),
        };
        let owner = RefcountedBodyOwner {
            opaque_prefix: [0; 10],
            body: &mut body,
        };
        let mut output = 0u8;

        CALLS.store(0, Ordering::SeqCst);
        CALLBACK.store(&mut callback as *mut RefcountedOwnerCallback as usize, Ordering::SeqCst);
        OUTPUT.store(&mut output as *mut u8 as usize, Ordering::SeqCst);
        SELECTOR.store(0xfeed_beef, Ordering::SeqCst);

        unsafe {
            refcounted_owner_callback_dispatch(&mut output, &owner, 0xfeed_beef);
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 3);
    }
}
