//! event_type_one_byte_store — original: `FUN_080da620` @ `0x080da620`.
//!
//! Load address: `0x080da620`; true size: 32 bytes (`0x20`), ending in `bx lr`
//! at `0x080da63c`, followed by the literal-pool word at `0x080da640` and the
//! next function at `0x080da644`. Raw ARM words establish two unconditional
//! and one predicated inbound `bl` calls; the body contains no calls.
//!
//! For event kind one, the routine copies the source byte to offset `0x20` of
//! the literal-pool-selected runtime state object, if that object pointer is
//! non-null; all other kinds do nothing and it returns zero. The state object's
//! concrete type and byte's meaning remain unrecovered. Deliberate deviation:
//! host builds use a private pointer seam for that runtime object; target builds
//! use the retail literal value `0x08a7563c` directly.

const RETAIL_EVENT_STATE_ADDRESS: usize = 0x08a7_563c;

#[cfg(not(target_os = "none"))]
static mut HOST_EVENT_STATE: *mut u8 = core::ptr::null_mut();

#[inline(always)]
fn event_state() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        RETAIL_EVENT_STATE_ADDRESS as *mut u8
    }
    #[cfg(not(target_os = "none"))]
    {
        unsafe { core::ptr::addr_of!(HOST_EVENT_STATE).read_volatile() }
    }
}

/// Stores `source[0]` at runtime-state offset `0x20` only for event kind one.
///
/// # Safety
///
/// When `event_kind` is one and the retail state pointer is non-null, `source`
/// must point to readable byte storage. The target's state object must have a
/// writable byte at offset `0x20`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_type_one_byte_store(event_kind: u32, source: *const u8) -> u32 {
    let state = event_state();
    if event_kind == 1 && !state.is_null() {
        unsafe { state.add(0x20).write(source.read()) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct StateReset(*mut u8);

    impl Drop for StateReset {
        fn drop(&mut self) {
            unsafe { HOST_EVENT_STATE = self.0 };
        }
    }

    #[test]
    fn kind_one_stores_the_source_byte_at_offset_0x20() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = [0x55u8; 0x22];
        let source = 0xa5;
        let reset = StateReset(unsafe { HOST_EVENT_STATE });
        unsafe { HOST_EVENT_STATE = state.as_mut_ptr() };

        assert_eq!(unsafe { event_type_one_byte_store(1, &source) }, 0);
        assert_eq!(state[0x1f], 0x55);
        assert_eq!(state[0x20], source);
        assert_eq!(state[0x21], 0x55);
        drop(reset);
    }

    #[test]
    fn other_kinds_do_not_dereference_source_or_modify_state() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = [0x55u8; 0x21];
        let reset = StateReset(unsafe { HOST_EVENT_STATE });
        unsafe { HOST_EVENT_STATE = state.as_mut_ptr() };

        assert_eq!(unsafe { event_type_one_byte_store(0, core::ptr::null()) }, 0);
        assert_eq!(unsafe { event_type_one_byte_store(2, core::ptr::null()) }, 0);
        assert_eq!(state[0x20], 0x55);
        drop(reset);
    }

    #[test]
    fn null_state_skips_the_store() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = 0xa5;
        let reset = StateReset(unsafe { HOST_EVENT_STATE });
        unsafe { HOST_EVENT_STATE = core::ptr::null_mut() };

        assert_eq!(unsafe { event_type_one_byte_store(1, &source) }, 0);
        drop(reset);
    }
}
