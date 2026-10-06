//! guarded_tagged_record_lookup — FUN_081689ac @ 0x081689ac.
//! True extent 128 bytes, [0x081689ac,0x08168a2c): 124 code bytes and
//! the root-slot literal 0x089ca674. The next entry begins with PUSH.
//! Whole-image A32 decoding verifies two inbound plain BLs (0x081b580c,
//! 0x081b5c6c), six outbound plain BLs, and zero predicated BLs either way.
//!
//! Initialize an empty tagged record, construct a scoped global guard,
//! query root+0x30 using the two-word key, copy the temporary record's payload
//! and the receiver's byte +0x44 into the result, then destroy both temporaries.
//! The query at 0x08051358 replaces r1 with r3 before using it, so the
//! constructor's incidental r1 return is not an argument dependency.
//!
//! Deviations: host-only explicit dependency injection replaces fixed RAM and
//! unported retail entries. Target uses raw root RAM and the existing record
//! initializer/empty destructor/guard destructor ports. The registry's
//! string-tail identification of 0x08155b4c conflicts with current raw words:
//! PUSH, BL 0x0820c304, vtable store, zero allocation store, POP, literal.
//! Its verified constructor role is used without claiming a product identity.

use crate::cxx::tagged_record::{TaggedRecord, tagged_record_init};
use crate::cxx::empty_destructor::empty_destructor;
use crate::util::scoped_global_guard_destroy::{ScopedGlobalGuard, scoped_global_guard_destroy};
use core::mem::MaybeUninit;

type ConstructGuard = unsafe extern "C" fn(*mut ScopedGlobalGuard) -> *mut ScopedGlobalGuard;
type Lookup = unsafe extern "C" fn(*const u32, u32, u32, u32) -> u32;

unsafe fn lookup_record(
    result: *mut TaggedRecord, receiver: *const u8, low: u32, high: u32,
    construct: ConstructGuard, lookup: Lookup,
) {
    unsafe {
        tagged_record_init(result, 0, 0);
        let mut guard = MaybeUninit::<ScopedGlobalGuard>::uninit();
        construct(guard.as_mut_ptr());
        #[cfg(target_os = "none")]
        let root = (0x089ca674 as *const *const u32).read();
        #[cfg(not(target_os = "none"))]
        let root = HOST_DEPENDENCIES.expect("retail lookup dependencies required on host").0;
        let context = root.add(0x30 / 4).read() as usize as *const u32;
        let payload = lookup(context, 0, low, high);
        let flag = receiver.add(0x44).read();
        let mut temporary = MaybeUninit::<TaggedRecord>::uninit();
        let temporary = tagged_record_init(temporary.as_mut_ptr(), payload, flag as u32);
        core::ptr::addr_of_mut!((*result).payload).write((*temporary).payload);
        core::ptr::addr_of_mut!((*result).flag).write((*temporary).flag);
        empty_destructor(temporary.cast());
        scoped_global_guard_destroy(guard.as_mut_ptr());
    }
}

/// Construct a tagged lookup result under the retail scoped global guard.
///
/// # Safety
/// Result must be aligned and writable for twelve bytes; receiver must be
/// readable through +0x44. On target, the application root and retail service
/// context must be initialized. Result/receiver aliasing follows retail store
/// order (the initial empty-record stores precede the receiver-byte read).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn guarded_tagged_record_lookup(
    result: *mut TaggedRecord, receiver: *const u8, low: u32, high: u32,
) {
    #[cfg(target_os = "none")]
    unsafe {
        lookup_record(result, receiver, low, high,
            core::mem::transmute(0x08155b4cusize),
            core::mem::transmute(0x08051358usize));
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        let (_, construct, lookup) = HOST_DEPENDENCIES.expect("retail lookup dependencies required on host");
        lookup_record(result, receiver, low, high, construct, lookup);
    }
}

#[cfg(not(target_os = "none"))]
static mut HOST_DEPENDENCIES: Option<(*const u32, ConstructGuard, Lookup)> = None;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::tagged_record::TAGGED_RECORD_DESCRIPTOR;
    extern crate std;
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    unsafe extern "C" fn construct(guard: *mut ScopedGlobalGuard) -> *mut ScopedGlobalGuard {
        // Exact target-width guard storage; no allocation in this fixture.
        unsafe { guard.cast::<u32>().write(0x08986aa0); guard.cast::<u32>().add(1).write(0); }
        guard
    }
    unsafe extern "C" fn lookup(context: *const u32, _: u32, low: u32, high: u32) -> u32 {
        assert_eq!(context as usize, 0x12345678);
        low.rotate_left(7) ^ high
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) { unsafe { HOST_DEPENDENCIES = None; } }
    }

    #[test]
    fn preserves_full_key_payload_flag_and_padding() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = Reset;
        let mut root = [0u32; 13];
        root[12] = 0x12345678;
        unsafe { HOST_DEPENDENCIES = Some((root.as_ptr(), construct, lookup)); }
        for (low, high, flag) in [(0, 0, 0), (u32::MAX, 0, 255), (0x81234567, 0xfedcba98, 128)] {
            let mut receiver = [0u8; 0x45];
            receiver[0x44] = flag;
            let mut storage = [0xa5a5a5a5u32; 3];
            unsafe { guarded_tagged_record_lookup(storage.as_mut_ptr().cast(), receiver.as_ptr(), low, high); }
            assert_eq!(storage, [TAGGED_RECORD_DESCRIPTOR, low.rotate_left(7) ^ high, 0xa5a5a500 | flag as u32]);
        }
    }

    #[test]
    fn initial_stores_precede_aliased_receiver_flag_read() {
        let _lock = LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _reset = Reset;
        let mut root = [0u32; 13];
        root[12] = 0x12345678;
        unsafe { HOST_DEPENDENCIES = Some((root.as_ptr(), construct, lookup)); }
        let mut storage = [0xeeeeeeeeu32; 20];
        // Result flag at byte 0x44 is also receiver flag: initial zero wins.
        unsafe { guarded_tagged_record_lookup(storage.as_mut_ptr().add(15).cast(), storage.as_ptr().cast(), 1, 2); }
        assert_eq!(storage[15], TAGGED_RECORD_DESCRIPTOR);
        assert_eq!(storage[16], 130);
        assert_eq!(storage[17], 0xeeeeee00);
        assert_eq!(storage[18], 0xeeeeeeee);
    }
}
