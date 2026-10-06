//! `FUN_0817904c` @ `0x0817904c`: vtable_08989104_destruct.
//!
//! True extent: 56 bytes, [0x0817904c,0x08179084), including the
//! 0x08989104 literal at +0x34. The next function starts with push at
//! 0x08179084. Three outgoing plain BLs, zero predicated BLs, and a tail B
//! to 0x0826c04c. Whole-image A32 decoding finds two inbound plain BLs
//! (0x08179040, 0x0828c1fc), zero predicated inbound BLs.
//!
//! Install the destruction vtable, clean embedded state, destroy the member
//! at +0x50, destroy the member 0x2c bytes before that destructor's return,
//! then chain to the base destructor 0x24 bytes before the second return.
//! Forward the base return unchanged. This is not a deleting destructor.
//!
//! Deliberate deviations: already ported member destructors are direct Rust
//! calls on target. The unported cleanup and base destructor retain their
//! verified retail addresses; no more specific class identity is asserted.
//! Host replacements avoid interpreting target-width object pointers as
//! native pointers. LLVM chooses call versus tail-branch lowering.

use core::ptr;

type Cleanup = unsafe extern "C" fn(*mut u32);
type Destroy = unsafe extern "C" fn(*mut u32) -> *mut u32;
const VTABLE_WORD: u32 = 0x0898_9104;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cleanup(_: *mut u32) {
    panic!("install composite destructor host cleanup")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_destroy(_: *mut u32) -> *mut u32 {
    panic!("install composite destructor host destructors")
}

/// Host substitutes for cleanup, the two member destructors, and base teardown.
#[cfg(not(target_os = "none"))]
pub static mut VTABLE_08989104_DESTRUCT_OPS: (Cleanup, Destroy, Destroy, Destroy) =
    (missing_cleanup, missing_destroy, missing_destroy, missing_destroy);

/// Destroys embedded state and members, returning the base destructor result.
///
/// # Safety
/// `this` must satisfy retail cleanup and both member destructor contracts.
/// Callee results must allow the original backwards pointer adjustments.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_08989104_destruct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        #[cfg(target_os = "none")]
        let (cleanup, first, second, base): (Cleanup, Destroy, Destroy, Destroy) = (
            core::mem::transmute(0x0817_8d64usize),
            super::vtable_08982424_destruct::vtable_08982424_destruct,
            super::vtable_089824fc_destruct::vtable_089824fc_destruct,
            core::mem::transmute(0x0826_c04cusize),
        );
        #[cfg(not(target_os = "none"))]
        let (cleanup, first, second, base) =
            ptr::read_volatile(ptr::addr_of!(VTABLE_08989104_DESTRUCT_OPS));
        cleanup(this);
        let member = first(this.add(0x50 / 4));
        let member = second(member.sub(0x2c / 4));
        base(member.sub(0x24 / 4))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    unsafe extern "C" fn cleanup(this: *mut u32) {
        assert_eq!(unsafe { this.read() }, VTABLE_WORD);
        unsafe { this.add(1).write(0); }
    }
    unsafe extern "C" fn first(member: *mut u32) -> *mut u32 {
        let root = unsafe { member.sub(20) };
        assert_eq!(unsafe { root.add(1).read() }, 0);
        unsafe { member.write(0); }
        // Exercise a returned receiver that differs from the input.
        unsafe { member.add(4) }
    }
    unsafe extern "C" fn second(member: *mut u32) -> *mut u32 {
        assert_eq!(unsafe { member.add(7).read() }, 0);
        unsafe { member.write(0); member.add(2) }
    }
    unsafe extern "C" fn base(member: *mut u32) -> *mut u32 {
        assert_eq!(unsafe { member.add(7).read() }, 0);
        unsafe { member.write(0); member.add(3) }
    }

    #[test]
    fn teardown_tracks_returned_receivers_and_preserves_unowned_words() {
        let _lock = LOCK.lock();
        unsafe {
            let old = ptr::read(ptr::addr_of!(VTABLE_08989104_DESTRUCT_OPS));
            ptr::addr_of_mut!(VTABLE_08989104_DESTRUCT_OPS).write((cleanup, first, second, base));
            for fill in [0, 0xffff_ffff, 0xfeed_face] {
                let mut object = [fill; 40];
                let root = object.as_mut_ptr();
                let result = vtable_08989104_destruct(root);
                assert_eq!(result, root.add(9));
                let mut expected = [fill; 40];
                expected[0] = VTABLE_WORD;
                for i in [1, 6, 13, 20] { expected[i] = 0; }
                assert_eq!(object, expected);
            }
            ptr::addr_of_mut!(VTABLE_08989104_DESTRUCT_OPS).write(old);
        }
    }
}
