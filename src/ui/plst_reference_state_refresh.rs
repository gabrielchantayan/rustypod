//! Cached PLST reference-validation state.

use core::ptr;
use crate::kernel::posix_mutex::{PosixMutex, posix_mutex_lock, posix_mutex_unlock};

const MUTEX_ADDRESS: usize = 0x08a7_74c0;
const STATE_OFFSET: usize = 0x1ae;
const REFERENCE_FLAG_OFFSET: usize = 0x1b2;
const REFERENCES_OFFSET: usize = 0x1b8;
const STATE_CHANGED_TAG: u32 = 0x7266_7363;

type ValidateReferences = unsafe extern "C" fn(u32, *mut u8, u32) -> u32;
type Notify = unsafe extern "C" fn(*mut u8, u32, *mut u8, u32, u32);
type MutexOp = unsafe extern "C" fn(*mut PosixMutex) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_validate_references(owner: u32, element: *mut u8, references: u32) -> u32 {
    let call: ValidateReferences = core::mem::transmute(0x0804_8e54usize);
    call(owner, element, references)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_validate_references(_: u32, _: *mut u8, _: u32) -> u32 {
    panic!("retail reference validator requires an installed host boundary")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify(list: *mut u8, tag: u32, context: *mut u8, payload: u32, extra: u32) {
    let call: Notify = core::mem::transmute(0x0806_6bb8usize);
    call(list, tag, context, payload, extra)
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_notify(_: *mut u8, _: u32, _: *mut u8, _: u32, _: u32) {
    panic!("retail tagged-list walker requires an installed host boundary")
}

/// External effects; host callers must replace the fixed-address mutex operations.
#[derive(Clone, Copy)]
pub struct PlstReferenceStateOps {
    pub lock: MutexOp,
    pub validate: ValidateReferences,
    pub notify: Notify,
    pub unlock: MutexOp,
}

pub const DEFAULT_PLST_REFERENCE_STATE_OPS: PlstReferenceStateOps = PlstReferenceStateOps {
    lock: posix_mutex_lock,
    validate: retail_validate_references,
    notify: retail_notify,
    unlock: posix_mutex_unlock,
};
pub static mut PLST_REFERENCE_STATE_OPS: PlstReferenceStateOps = DEFAULT_PLST_REFERENCE_STATE_OPS;

/// plst_reference_state_refresh — `FUN_0806d7dc` @ `0x0806d7dc`.
/// True extent: 156 bytes, [0x0806d7dc,0x0806d878), including eight literal
/// bytes after 148 instruction bytes. Two incoming plain BLs, three outgoing
/// plain BLs, zero predicated BLs; final B tail-calls mutex unlock.
///
/// Lock the shared resource mutex, ignoring its status. Keep a nonzero cached
/// state unless forced. Otherwise default to state 1; when the reference flag
/// and reference word are nonzero, expose state 6 during recursive validation
/// of (owner, element, references), then store its low byte. Notify the parent's
/// list only when a previously nonzero state differs from the full u32 result.
/// Return unlock status, not the validation result.
///
/// Deviations: use canonical mutex ports instead of verified alias veneers
/// 0x082621a8/0x082621ac. The unported validator 0x08048e54 and tagged-list
/// walker 0x08066bb8 retain verified retail addresses behind injectable ops.
/// Ghidra's spurious third input is omitted: r2 is loaded from +0x1b8 on the
/// only path that consumes it. No firmware state or notification rule is changed.
///
/// # Safety
/// `element` is writable, four-byte-aligned target-layout storage through
/// +0x1bb. Owner/reference words and parent+0xbac must satisfy installed callees.
/// The fixed-address mutex must exist, or host operations must be installed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn plst_reference_state_refresh(element: *mut u8, force: u32) -> u32 {
    let ops = ptr::read_volatile(ptr::addr_of!(PLST_REFERENCE_STATE_OPS));
    let mutex = MUTEX_ADDRESS as *mut PosixMutex;
    (ops.lock)(mutex);
    let old_state = element.add(STATE_OFFSET).read();
    if old_state == 0 || force != 0 {
        let mut state = 1;
        if element.add(REFERENCE_FLAG_OFFSET).read() != 0 {
            let references = element.add(REFERENCES_OFFSET).cast::<u32>().read();
            if references != 0 {
                element.add(STATE_OFFSET).write(6);
                state = (ops.validate)(element.add(0xc).cast::<u32>().read(), element, references);
            }
        }
        element.add(STATE_OFFSET).write(state as u8);
        if old_state != 0 && state != u32::from(old_state) {
            let parent = element.add(8).cast::<u32>().read();
            (ops.notify)(parent.wrapping_add(0xbac) as usize as *mut u8, STATE_CHANGED_TAG, ptr::null_mut(), 0, 0);
        }
    }
    (ops.unlock)(mutex)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use parking_lot::Mutex;
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut VALIDATION_RESULT: u32 = 0;
    static mut EVENTS: std::vec::Vec<u8> = std::vec::Vec::new();

    unsafe extern "C" fn lock(_: *mut PosixMutex) -> u32 { EVENTS.push(1); 9 }
    unsafe extern "C" fn unlock(_: *mut PosixMutex) -> u32 { EVENTS.push(4); 0x35 }
    unsafe extern "C" fn validate(owner: u32, element: *mut u8, references: u32) -> u32 {
        assert_eq!(owner, 0x1234);
        assert_eq!(references, 0x5678);
        assert_eq!(element.add(STATE_OFFSET).read(), 6);
        // Recursive validation must see the in-progress state and skip re-entry.
        assert_eq!(plst_reference_state_refresh(element, 0), 0x35);
        EVENTS.push(2);
        VALIDATION_RESULT
    }
    unsafe extern "C" fn notify(list: *mut u8, tag: u32, context: *mut u8, payload: u32, extra: u32) {
        assert_eq!(list as usize, 0x10bac);
        assert_eq!((tag, context as usize, payload, extra), (STATE_CHANGED_TAG, 0, 0, 0));
        EVENTS.push(3);
    }
    struct Restore(PlstReferenceStateOps);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { PLST_REFERENCE_STATE_OPS = self.0; } }
    }

    #[test]
    fn cached_forced_recursive_and_full_width_transitions() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            let _restore = Restore(PLST_REFERENCE_STATE_OPS);
            PLST_REFERENCE_STATE_OPS = PlstReferenceStateOps { lock, validate, notify, unlock };
            // old, force, flag, references, result, final byte, validate, notify
            let cases = [
                (0, 0, 0, 0x5678, 5, 1, false, false),
                (0, 0, 1, 0, 5, 1, false, false),
                (0, 0, 1, 0x5678, 5, 5, true, false),
                (5, 0, 1, 0x5678, 1, 5, false, false),
                (5, 2, 0, 0x5678, 5, 1, false, true),
                (5, 1, 1, 0x5678, 5, 5, true, false),
                (5, 1, 1, 0x5678, 0x105, 5, true, true),
                (5, 1, 1, 0x5678, 0, 0, true, true),
                (6, 0, 1, 0x5678, 1, 6, false, false),
            ];
            for (old, force, flag, references, result, final_byte, validated, notified) in cases {
                let mut storage = [0xa5a5_a5a5u32; 0x1bc / 4];
                let element = storage.as_mut_ptr().cast::<u8>();
                element.add(8).cast::<u32>().write(0x10000);
                element.add(0xc).cast::<u32>().write(0x1234);
                element.add(STATE_OFFSET).write(old);
                element.add(REFERENCE_FLAG_OFFSET).write(flag);
                element.add(REFERENCES_OFFSET).cast::<u32>().write(references);
                let before = storage;
                EVENTS.clear();
                VALIDATION_RESULT = result;
                assert_eq!(plst_reference_state_refresh(element, force), 0x35);
                assert_eq!(element.add(STATE_OFFSET).read(), final_byte);
                let mut expected = std::vec![1];
                if validated { expected.extend_from_slice(&[1, 4, 2]); }
                if notified { expected.push(3); }
                expected.push(4);
                assert_eq!(&*ptr::addr_of!(EVENTS), &expected);
                element.add(STATE_OFFSET).write(old);
                assert_eq!(storage, before, "only the state byte may change");
            }
        }
    }
}
