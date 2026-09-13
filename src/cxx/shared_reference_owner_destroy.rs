//! `shared_reference_owner_destroy` — original: `FUN_0826f844` @
//! **0x0826f844** (24 bytes; `0x0826f844..0x0826f85c`).
//!
//! Raw ARM establishes the extent: the `pop {r4,pc}` at `0x0826f858` is
//! followed by the separately linked function beginning `ldr r0,[r0,#4]` at
//! `0x0826f85c`; there is no literal pool. Decoding every ARM B/BL-immediate
//! word in `osos.dec` finds six incoming direct `bl` call sites, all
//! unconditional (at `0x0816306c`, `0x08163080`, `0x08163094`, `0x081630a8`,
//! `0x081630bc`, and `0x081630d0`), with no predicated forms.
//!
//! # Algorithm
//!
//! This C++ destructor preserves `owner`, releases its embedded shared
//! reference at target offset `+0x10` through `FUN_0839d550`, then returns
//! the original owner pointer. The enclosing object's concrete type is not
//! recoverable from this leaf, so only the accessed target-layout prefix is
//! represented here. Deliberate deviation: `FUN_0839d550` is absent from
//! `names.yaml`; target builds call its resident retailOS address directly,
//! while host tests install a volatile recorder to observe the exact field
//! passed to it.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_SHARED_REFERENCE_RELEASE: usize = 0x0839_d550;

/// Target-layout prefix consumed by [`shared_reference_owner_destroy`].
///
/// All fields are firmware-width words, including the reference identity, so
/// `shared_reference` stays at target offset `+0x10` on 64-bit hosts.
#[repr(C)]
pub struct SharedReferenceOwner {
    opaque_prefix: [u32; 4],
    pub shared_reference: u32,
}

/// ABI of the unported shared-reference release helper at `0x0839d550`.
pub type SharedReferenceRelease = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_shared_reference_release(reference: *mut u32) {
    let release: SharedReferenceRelease = core::mem::transmute(RETAIL_SHARED_REFERENCE_RELEASE);
    release(reference);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_shared_reference_release(_reference: *mut u32) {
    panic!("shared_reference_owner_destroy requires release helper 0x0839d550")
}

/// Active host boundary for unported `FUN_0839d550`.
#[cfg(not(target_os = "none"))]
pub static mut SHARED_REFERENCE_RELEASE: SharedReferenceRelease = missing_shared_reference_release;

#[inline(always)]
unsafe fn shared_reference_release(reference: *mut u32) {
    #[cfg(target_os = "none")]
    retail_shared_reference_release(reference);

    #[cfg(not(target_os = "none"))]
    {
        let release = core::ptr::read_volatile(addr_of!(SHARED_REFERENCE_RELEASE));
        release(reference);
    }
}

/// Destroys `owner`'s embedded shared reference and returns `owner`.
///
/// `owner` must be valid, aligned, and writable through its word at target
/// offset `+0x10`; the release helper owns the pointed-to reference's stronger
/// validity requirements. The raw ARM has no NULL guard before taking this
/// field address.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.shared_reference_owner_destroy_0826f844")]
#[inline(never)]
pub unsafe extern "C" fn shared_reference_owner_destroy(
    owner: *mut SharedReferenceOwner,
) -> *mut SharedReferenceOwner {
    shared_reference_release(core::ptr::addr_of_mut!((*owner).shared_reference));
    owner
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};

    static RELEASE_LOCK: Mutex<()> = Mutex::new(());
    static mut RELEASED_REFERENCE: *mut u32 = core::ptr::null_mut();
    static mut RELEASE_CALLS: u32 = 0;

    unsafe extern "C" fn recording_release(reference: *mut u32) {
        RELEASED_REFERENCE = reference;
        RELEASE_CALLS += 1;
        reference.write(0);
    }

    fn install_recorder() -> MutexGuard<'static, ()> {
        let guard = RELEASE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            addr_of_mut!(RELEASED_REFERENCE).write(core::ptr::null_mut());
            addr_of_mut!(RELEASE_CALLS).write(0);
            addr_of_mut!(SHARED_REFERENCE_RELEASE).write(recording_release);
        }
        guard
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                addr_of_mut!(SHARED_REFERENCE_RELEASE).write(missing_shared_reference_release);
                addr_of_mut!(RELEASED_REFERENCE).write(core::ptr::null_mut());
                addr_of_mut!(RELEASE_CALLS).write(0);
            }
        }
    }

    #[test]
    fn releases_the_embedded_reference_and_returns_owner() {
        let _guard = install_recorder();
        let _reset = Reset;
        let mut owner = SharedReferenceOwner {
            opaque_prefix: [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444],
            shared_reference: 0x89ab_cdef,
        };

        let returned = unsafe { shared_reference_owner_destroy(addr_of_mut!(owner)) };

        assert_eq!(returned, addr_of_mut!(owner));
        assert_eq!(unsafe { addr_of!(RELEASE_CALLS).read() }, 1);
        assert_eq!(unsafe { addr_of!(RELEASED_REFERENCE).read() }, addr_of_mut!(owner.shared_reference));
        assert_eq!(owner.shared_reference, 0);
        assert_eq!(owner.opaque_prefix, [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]);
    }
}