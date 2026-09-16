//! `object_commit_touch` — original: `FUN_08050eb4` @ **0x08050eb4**.
//!
//! # Raw extent and call sites
//!
//! The executable extent is exactly **80 bytes**
//! (`0x08050eb4..0x08050f04`): the next separately linked function begins
//! with `push {r4-r6, lr}` at `0x08050f04`. Decoding every immediate ARM
//! `B`/`BL` word in `work/firmware/osos.dec` (load base `0x08000000`) finds
//! **5 `bl` callers**: four unconditional at `0x0804744c`, `0x0804849c`,
//! `0x0805d9e4`, and `0x0806c8cc`, plus one predicated `blgt` at
//! `0x08431eec`; there are no direct `b` tail callers. The body makes two
//! unconditional `bl` calls (`0x08041104` and the ported
//! `0x08054fc4`) and one `b` tail branch to `0x08050f4c`.
//!
//! # Algorithm
//!
//! The object carries a modification timestamp word at `+0x08`, a flags
//! halfword at `+0xb0`, and a pointer-to-pointer at `+0x158` whose final
//! target is the backing store object. It first asks the backing store to
//! commit any pending record (`0x08041104`, which writes the dirty record
//! out and clears its dirty bit) and sign-extends that status from an
//! `i16` (`mov r0, r0, lsl #16; movs r0, r0, asr #16`); a nonzero status is
//! returned immediately. When the commit reports success and the backing
//! store's byte at `+0x0c` has bit 7 set, the object is marked modified:
//! the low byte of the `+0xb0` flags halfword is ORed with `0xff`, the
//! current UTC-corrected Macintosh-epoch timestamp is stored at `+0x08`,
//! and the tail target `0x08050f4c` revalidates the object's `0x482b`
//! record magic, returning its result. Otherwise the function returns 0.
//!
//! # Deliberate deviations
//!
//! Callees `0x08041104` and `0x08050f4c` are not ported. Device builds use
//! literal veneers to their verified load addresses; host builds use
//! fixture seams for those two calls and for the ported timestamp query,
//! matching the established seam pattern. Ghidra's decompile misplaces the
//! flags halfword at `param_1[0]` and the mask as `0xff00`; the raw words
//! `ldrh r0, [r4, #0xb0]; orr r0, r0, #0xff; strh r0, [r4, #0xb0]` are
//! authoritative.

#[cfg(not(target_arch = "arm"))]
use core::ptr;

/// Byte offset of the object's modification timestamp word.
const TIMESTAMP_OFFSET: usize = 0x08;
/// Byte offset of the object's flags halfword.
const FLAGS_OFFSET: usize = 0xb0;
/// Byte offset of the object's pointer-to-pointer to the backing store.
const BACKEND_PTR_OFFSET: usize = 0x158;
/// Backing-store byte whose bit 7 gates the touch path.
const BACKEND_GATE_OFFSET: usize = 0x0c;
/// Bit 7 of the backing-store gate byte.
const BACKEND_TOUCH_GATE: u8 = 0x80;
/// Low-byte flag mask written on touch.
const TOUCH_FLAGS: u16 = 0x00ff;

/// ABI of the unported pending-record commit at `0x08041104`.
#[cfg(not(target_arch = "arm"))]
type RetailBackendCommit = unsafe extern "C" fn(backend: *mut u8) -> i32;

#[cfg(target_arch = "arm")]
extern "C" {
    fn retail_backend_record_commit(backend: *mut u8) -> i32;
    fn retail_record_magic_validate(object: *mut u8) -> i32;
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_backend_record_commit(_backend: *mut u8) -> i32 {
    panic!("object_commit_touch requires a host backend-commit fixture")
}

#[cfg(not(target_arch = "arm"))]
static mut RETAIL_BACKEND_RECORD_COMMIT: RetailBackendCommit =
    missing_retail_backend_record_commit;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_retail_record_magic_validate(_object: *mut u8) -> i32 {
    panic!("object_commit_touch requires a host record-validate fixture")
}

#[cfg(not(target_arch = "arm"))]
static mut RETAIL_RECORD_MAGIC_VALIDATE: unsafe extern "C" fn(*mut u8) -> i32 =
    missing_retail_record_magic_validate;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_current_timestamp() -> i32 {
    panic!("object_commit_touch requires a host timestamp fixture")
}

#[cfg(not(target_arch = "arm"))]
static mut CURRENT_TIMESTAMP: unsafe extern "C" fn() -> i32 = missing_current_timestamp;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn backend_record_commit(backend: *mut u8) -> i32 {
    unsafe { retail_backend_record_commit(backend) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn backend_record_commit(backend: *mut u8) -> i32 {
    unsafe { ptr::read_volatile(ptr::addr_of!(RETAIL_BACKEND_RECORD_COMMIT))(backend) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn record_magic_validate(object: *mut u8) -> i32 {
    unsafe { retail_record_magic_validate(object) }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn record_magic_validate(object: *mut u8) -> i32 {
    unsafe { ptr::read_volatile(ptr::addr_of!(RETAIL_RECORD_MAGIC_VALIDATE))(object) }
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn current_timestamp() -> i32 {
    unsafe {
        crate::time::current_mac_epoch_seconds::current_mac_epoch_seconds_with_utc_offset()
    }
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn current_timestamp() -> i32 {
    unsafe { ptr::read_volatile(ptr::addr_of!(CURRENT_TIMESTAMP))() }
}

// The port lives in the payload, so these literal veneers preserve the
// retail AAPCS calls into the original bodies at their fixed load
// addresses.
#[cfg(target_arch = "arm")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_backend_record_commit
    .type retail_backend_record_commit, %function
retail_backend_record_commit:
    ldr     pc, [pc, #-4]
    .word   0x08041104
    .size retail_backend_record_commit, . - retail_backend_record_commit

    .p2align 2
    .globl retail_record_magic_validate
    .type retail_record_magic_validate, %function
retail_record_magic_validate:
    ldr     pc, [pc, #-4]
    .word   0x08050f4c
    .size retail_record_magic_validate, . - retail_record_magic_validate
"#
);

/// object_commit_touch — original: `FUN_08050eb4` @ `0x08050eb4`
/// (**80 bytes, 0x08050eb4..0x08050f04; 4 unconditional `bl` callers plus 1
/// predicated `blgt` caller; no `b` tail callers**).
///
/// Commits the backing store's pending record and, when that succeeds and
/// the backing store's gate byte requests it, marks the object modified:
/// sets the low byte of its `+0xb0` flags halfword, stamps the current
/// UTC-corrected Macintosh-epoch timestamp at `+0x08`, and revalidates the
/// record magic via the tail target, returning its status.
///
/// Returns the backing-store commit status sign-extended from an `i16`
/// when nonzero, otherwise the tail validation status on touch, otherwise 0.
///
/// # Safety
///
/// `object` must point to a writable object at least `0x15c + 4` bytes
/// long whose word at `+0x158` holds a valid pointer to a pointer to the
/// backing-store object, which must be readable at byte `+0x0c` and
/// acceptable to the firmware commit routine at `0x08041104`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.object_commit_touch")]
pub unsafe extern "C" fn object_commit_touch(object: *mut u8) -> i32 {
    let backend = unsafe { **(object.add(BACKEND_PTR_OFFSET) as *mut *mut *mut u8) };

    // The original truncates the commit status with `mov r0, r0, lsl #16;
    // movs r0, r0, asr #16`: an i16 sign extension, not a u16 truncation.
    let status = unsafe { backend_record_commit(backend) } as i16 as i32;
    if status != 0 {
        return status;
    }

    if unsafe { *backend.add(BACKEND_GATE_OFFSET) } & BACKEND_TOUCH_GATE == 0 {
        return 0;
    }

    let flags = unsafe { object.add(FLAGS_OFFSET) as *mut u16 };
    unsafe { *flags = *flags | TOUCH_FLAGS };
    unsafe { *(object.add(TIMESTAMP_OFFSET) as *mut i32) = current_timestamp() };

    unsafe { record_magic_validate(object) }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static COMMIT_CALLS: AtomicU32 = AtomicU32::new(0);
    static COMMIT_BACKEND: AtomicU32 = AtomicU32::new(0);
    static COMMIT_RESULT: AtomicI32 = AtomicI32::new(0);
    static VALIDATE_CALLS: AtomicU32 = AtomicU32::new(0);
    static VALIDATE_OBJECT: AtomicU32 = AtomicU32::new(0);
    static VALIDATE_RESULT: AtomicI32 = AtomicI32::new(0);
    static TIMESTAMP_CALLS: AtomicU32 = AtomicU32::new(0);
    static TIMESTAMP_VALUE: AtomicI32 = AtomicI32::new(0);

    /// Host fake of the touched object: bytes, with a host pointer stored
    /// at `+0x158` pointing at `backend_link`, which points at `backend`.
    #[repr(C, align(8))]
    struct Fixture {
        object: [u8; 0x160],
        backend_link: *mut u8,
        backend: [u8; 0x10],
    }

    impl Fixture {
        /// Boxed so the self-referential links stay valid; a plain `Fixture`
        /// return would move the struct and invalidate the stored addresses.
        fn new(gate: u8) -> std::boxed::Box<Fixture> {
            let mut fixture = std::boxed::Box::new(Fixture {
                object: [0; 0x160],
                backend_link: ptr::null_mut(),
                backend: [0; 0x10],
            });
            fixture.backend[BACKEND_GATE_OFFSET] = gate;
            fixture.backend_link = fixture.backend.as_mut_ptr();
            unsafe {
                *(fixture.object.as_mut_ptr().add(BACKEND_PTR_OFFSET) as *mut *mut *mut u8) =
                    ptr::addr_of_mut!(fixture.backend_link);
            }
            fixture
        }

        fn flags(&self) -> u16 {
            unsafe { *(self.object.as_ptr().add(FLAGS_OFFSET) as *const u16) }
        }

        fn timestamp(&self) -> i32 {
            unsafe { *(self.object.as_ptr().add(TIMESTAMP_OFFSET) as *const i32) }
        }
    }

    unsafe extern "C" fn recording_backend_record_commit(backend: *mut u8) -> i32 {
        COMMIT_CALLS.fetch_add(1, Ordering::Relaxed);
        COMMIT_BACKEND.store(backend as u32, Ordering::Relaxed);
        COMMIT_RESULT.load(Ordering::Relaxed)
    }

    unsafe extern "C" fn recording_record_magic_validate(object: *mut u8) -> i32 {
        VALIDATE_CALLS.fetch_add(1, Ordering::Relaxed);
        VALIDATE_OBJECT.store(object as u32, Ordering::Relaxed);
        VALIDATE_RESULT.load(Ordering::Relaxed)
    }

    unsafe extern "C" fn recording_current_timestamp() -> i32 {
        TIMESTAMP_CALLS.fetch_add(1, Ordering::Relaxed);
        TIMESTAMP_VALUE.load(Ordering::Relaxed)
    }

    struct Mock {
        previous_commit: RetailBackendCommit,
        previous_validate: unsafe extern "C" fn(*mut u8) -> i32,
        previous_timestamp: unsafe extern "C" fn() -> i32,
        _lock: MutexGuard<'static, ()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(
                    ptr::addr_of_mut!(RETAIL_BACKEND_RECORD_COMMIT),
                    self.previous_commit,
                );
                ptr::write_volatile(
                    ptr::addr_of_mut!(RETAIL_RECORD_MAGIC_VALIDATE),
                    self.previous_validate,
                );
                ptr::write_volatile(ptr::addr_of_mut!(CURRENT_TIMESTAMP), self.previous_timestamp);
            }
        }
    }

    fn install(commit_result: i32, validate_result: i32, timestamp: i32) -> Mock {
        let lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous_commit =
            unsafe { ptr::read_volatile(ptr::addr_of!(RETAIL_BACKEND_RECORD_COMMIT)) };
        let previous_validate =
            unsafe { ptr::read_volatile(ptr::addr_of!(RETAIL_RECORD_MAGIC_VALIDATE)) };
        let previous_timestamp = unsafe { ptr::read_volatile(ptr::addr_of!(CURRENT_TIMESTAMP)) };
        unsafe {
            ptr::write_volatile(
                ptr::addr_of_mut!(RETAIL_BACKEND_RECORD_COMMIT),
                recording_backend_record_commit,
            );
            ptr::write_volatile(
                ptr::addr_of_mut!(RETAIL_RECORD_MAGIC_VALIDATE),
                recording_record_magic_validate,
            );
            ptr::write_volatile(
                ptr::addr_of_mut!(CURRENT_TIMESTAMP),
                recording_current_timestamp,
            );
        }
        COMMIT_CALLS.store(0, Ordering::Relaxed);
        COMMIT_BACKEND.store(0, Ordering::Relaxed);
        COMMIT_RESULT.store(commit_result, Ordering::Relaxed);
        VALIDATE_CALLS.store(0, Ordering::Relaxed);
        VALIDATE_OBJECT.store(0, Ordering::Relaxed);
        VALIDATE_RESULT.store(validate_result, Ordering::Relaxed);
        TIMESTAMP_CALLS.store(0, Ordering::Relaxed);
        TIMESTAMP_VALUE.store(timestamp, Ordering::Relaxed);
        Mock {
            previous_commit,
            previous_validate,
            previous_timestamp,
            _lock: lock,
        }
    }

    #[test]
    fn nonzero_commit_status_is_sign_extended_from_i16_and_short_circuits() {
        let _mock = install(0x0000_8001, 0x21, 999);
        let mut fixture = Fixture::new(BACKEND_TOUCH_GATE);

        let result = unsafe { object_commit_touch(fixture.object.as_mut_ptr()) };

        assert_eq!(result, -32767);
        assert_eq!(COMMIT_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(
            COMMIT_BACKEND.load(Ordering::Relaxed),
            fixture.backend.as_ptr() as u32
        );
        assert_eq!(fixture.flags(), 0);
        assert_eq!(fixture.timestamp(), 0);
        assert_eq!(TIMESTAMP_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(VALIDATE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn positive_i16_commit_status_is_zero_extended() {
        let _mock = install(0x1234_5678, 0x21, 999);
        let mut fixture = Fixture::new(0);

        let result = unsafe { object_commit_touch(fixture.object.as_mut_ptr()) };

        assert_eq!(result, 0x5678);
        assert_eq!(COMMIT_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(VALIDATE_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(TIMESTAMP_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn clear_gate_byte_returns_zero_without_touching() {
        let _mock = install(0, 0x21, 999);
        let mut fixture = Fixture::new(0x7f);

        let result = unsafe { object_commit_touch(fixture.object.as_mut_ptr()) };

        assert_eq!(result, 0);
        assert_eq!(COMMIT_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.flags(), 0);
        assert_eq!(fixture.timestamp(), 0);
        assert_eq!(TIMESTAMP_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(VALIDATE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn set_gate_marks_flags_stamps_timestamp_and_tail_validates() {
        let _mock = install(0, 0x21, -1_234_567_890);
        let mut fixture = Fixture::new(0xff);
        let object_ptr = fixture.object.as_mut_ptr();
        unsafe {
            *(object_ptr.add(FLAGS_OFFSET) as *mut u16) = 0x5a00;
        }

        let result = unsafe { object_commit_touch(object_ptr) };

        assert_eq!(result, 0x21);
        assert_eq!(fixture.flags(), 0x5aff);
        assert_eq!(fixture.timestamp(), -1_234_567_890);
        assert_eq!(TIMESTAMP_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(VALIDATE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(VALIDATE_OBJECT.load(Ordering::Relaxed), object_ptr as u32);
    }
}
