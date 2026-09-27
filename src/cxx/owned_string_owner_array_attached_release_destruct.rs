//! `owned_string_owner_array_attached_release_destruct` — retailOS
//! `FUN_083d0f80` @ **0x083d0f80** (56 bytes).
//!
//! Raw `osos.dec` decodes fourteen A32 words from `0x083d0f80` through the
//! tail branch at `0x083d0fb4`; `0x083d0fb8` is vtable literal `0x089a4998`,
//! and `push {r4-r6,lr}` at `0x083d0fbc` opens the next function. Whole-image
//! ARM branch decoding finds two inbound plain `bl` sites and no predicated
//! inbound `bl` sites. The body has one plain `bl` to
//! `owned_string_owner_array_release` @ `0x083d0ec0`, one predicated indirect
//! `blxne` through the non-NULL attached object's vtable slot `+0x1c`, then a
//! tail branch to `observable_array_destruct` @ `0x08271d2c`.
//!
//! # Algorithm
//!
//! Re-plants the derived vtable, conditionally releases the attached object at
//! `+0x14`, releases owned string-owner cells, and tail-chains into the
//! observable-array destructor.
//!
//! Deliberate deviations: host builds use seams for the target-width virtual
//! call and the already ported cell-release operation; target builds invoke
//! both recovered Rust call boundaries directly. Rust represents the predicated
//! `blx` and tail branch as ordinary control flow.

use crate::cxx::observable_array::observable_array_destruct;

const VTABLE_WORD: u32 = 0x089a_4998;
const ATTACHED_OBJECT_WORD: usize = 0x14 / 4;

type ReleaseAttachedObject = unsafe extern "C" fn(*mut u8);
type ReleaseOwnedStrings = unsafe extern "C" fn(*mut u32);

#[cfg(target_os = "none")]
unsafe fn release_attached_object(object: *mut u8) {
    let vtable = unsafe { object.cast::<*const u32>().read_volatile() };
    let release = unsafe {
        vtable
            .add(0x1c / 4)
            .cast::<unsafe extern "C" fn(*mut u8)>()
            .read_volatile()
    };
    unsafe { release(object) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_attached_object(_: *mut u8) {
    panic!("install owned string-owner array destructor host seams before calling this port")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_owned_strings(_: *mut u32) {
    panic!("install owned string-owner array destructor host seams before calling this port")
}

/// Host replacements for the target-width virtual release and the direct
/// `owned_string_owner_array_release` call.
#[cfg(not(target_os = "none"))]
pub static mut OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS:
    (ReleaseAttachedObject, ReleaseOwnedStrings) =
    (missing_release_attached_object, missing_release_owned_strings);

/// Destroys an owned string-owner observable array with an optional attached object.
///
/// # Safety
///
/// `this` must point to a writable target-layout derived observable array with a
/// readable attached-object word at `+0x14`. A non-NULL attached object must
/// expose a callable vtable slot at `+0x1c`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_string_owner_array_attached_release_destruct(
    this: *mut u32,
) -> *mut u32 {
    unsafe {
        this.write_volatile(VTABLE_WORD);
        let attached = this.add(ATTACHED_OBJECT_WORD).read_volatile() as usize as *mut u8;

        #[cfg(target_os = "none")]
        {
            if !attached.is_null() {
                release_attached_object(attached);
            }
            crate::cxx::owned_string_owner_array_release::owned_string_owner_array_release(
                this.cast(),
            );
        }
        #[cfg(not(target_os = "none"))]
        {
            let (release, release_owned_strings) = core::ptr::read_volatile(
                core::ptr::addr_of!(OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS),
            );
            if !attached.is_null() {
                release(attached);
            }
            release_owned_strings(this);
        }

        observable_array_destruct(this.cast()).cast()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [u32; 2] = [0; 2];
    static mut RELEASED: *mut u8 = core::ptr::null_mut();
    static mut RELEASED_ARRAY: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_release(object: *mut u8) {
        unsafe {
            CALLS[0] += 1;
            RELEASED = object;
        }
    }

    unsafe extern "C" fn record_owned_string_release(array: *mut u32) {
        unsafe {
            CALLS[1] += 1;
            RELEASED_ARRAY = array;
        }
    }

    #[test]
    fn releases_attached_object_before_owned_strings_and_base() {
        let _lock = LOCK.lock();
        unsafe {
            let old = core::ptr::read_volatile(core::ptr::addr_of!(
                OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS
            ));
            core::ptr::addr_of_mut!(OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS)
                .write((record_release, record_owned_string_release));
            CALLS = [0; 2];
            RELEASED = core::ptr::null_mut();
            RELEASED_ARRAY = core::ptr::null_mut();

            let mut object = [0xfeed_face; 6];
            object[ATTACHED_OBJECT_WORD] = 0x1234_5000;
            object[1] = 0;
            object[2] = 0;
            object[3] = 0;
            let result = owned_string_owner_array_attached_release_destruct(object.as_mut_ptr());

            core::ptr::addr_of_mut!(OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS)
                .write(old);
            assert_eq!(result, object.as_mut_ptr());
            assert_eq!(object[0], crate::cxx::observable_array::OBSERVABLE_ARRAY_VTABLE);
            assert_eq!(object[1], 0);
            assert_eq!(object[2], 0);
            assert_eq!(object[ATTACHED_OBJECT_WORD], 0x1234_5000);
            assert_eq!(CALLS, [1, 1]);
            assert_eq!(RELEASED, 0x1234_5000usize as *mut u8);
            assert_eq!(RELEASED_ARRAY, object.as_mut_ptr());
        }
    }

    #[test]
    fn skips_virtual_release_for_null_attached_object() {
        let _lock = LOCK.lock();
        unsafe {
            let old = core::ptr::read_volatile(core::ptr::addr_of!(
                OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS
            ));
            core::ptr::addr_of_mut!(OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS)
                .write((record_release, record_owned_string_release));
            CALLS = [0; 2];

            let mut object = [0u32; 6];
            owned_string_owner_array_attached_release_destruct(object.as_mut_ptr());

            core::ptr::addr_of_mut!(OWNED_STRING_OWNER_ARRAY_ATTACHED_RELEASE_DESTRUCT_OPS)
                .write(old);
            assert_eq!(CALLS, [0, 1]);
        }
    }
}
