//! Access to the state word owned by an opaque application singleton.
//!
//! `singleton_state_get` — original: `FUN_08086df0` @ 0x08086df0 (16 bytes).
//! Raw ARM is `push {r4,lr}; bl 0x08127954; pop {r4,lr}; b 0x0829919c`.
//! The tail helper at 0x0829919c is `ldr r0,[r0,#0x18]; bx lr`, so the
//! source-level operation fetches the singleton base object, then returns its
//! word at +0x18. The base accessor reads the `+4` slot in the global block
//! at 0x089cfda0, so this wrapper neither constructs nor validates either
//! object. Its two direct callers use the returned word as a vtable-bearing
//! state object, but its concrete class remains unknown.

/// Firmware globals block read by [`singleton_state_base_get`].
///
/// `DAT_08127960`, the literal at 0x08127960, is 0x089cfda0. The requested
/// singleton base pointer is its `+0x04` slot.
#[cfg(target_os = "none")]
const SINGLETON_STATE_GLOBALS: *const u8 = 0x089c_fda0 as *const u8;

/// Host representation of the firmware globals block's `+0x04` base slot.
///
/// A 64-bit host cannot store its native pointers in the retailOS 32-bit
/// globals layout, so the slot is modeled directly rather than as bytes.
#[cfg(not(target_os = "none"))]
pub(crate) static mut HOST_SINGLETON_STATE_BASE: *mut u8 = core::ptr::null_mut();

/// singleton_state_base_get — original: `FUN_08127954` @ 0x08127954
/// (12 bytes).
///
/// Raw ARM is `ldr r0,[0x08127960]; ldr r0,[r0,#0x4]; bx lr`: load the
/// globals-block literal 0x089cfda0, then return its untyped `+0x04` object
/// slot without construction or a NULL check. ARM builds read that exact
/// 32-bit firmware slot. Host builds use [`HOST_SINGLETON_STATE_BASE`] to
/// preserve pointer width for behavior tests.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_state_base_get() -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        return unsafe {
            (SINGLETON_STATE_GLOBALS.add(4) as *const *mut u8).read_volatile()
        };
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        core::ptr::addr_of!(HOST_SINGLETON_STATE_BASE).read_volatile()
    }
}

/// singleton_state_get — original: `FUN_08086df0` @ 0x08086df0 (16 bytes).
///
/// Calls [`singleton_state_base_get`] before loading and returning that
/// object's raw word at offset +0x18, incorporating the original's tail
/// helper `FUN_0829919c`. No NULL or validity check is introduced for either
/// the returned object or its word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn singleton_state_get() -> u32 {
    let singleton = unsafe { singleton_state_base_get() };
    unsafe { (singleton.add(0x18) as *const u32).read() }
}

/// singleton_state_noop — original: `FUN_081279a0` @ 0x081279a0.
///
/// True extent: 4 bytes, ending at the next prologue at 0x081279a4.
/// Raw ARM is solely `bx lr`: zero outbound BLs; two plain inbound BLs
/// (0x08199528, 0x0819afe8), zero predicated inbound BLs, and no raw
/// address-valued DATA references. Both callers pass the singleton base
/// in r0 and 1 in r1, then overwrite r0 without consuming its value.
/// Does not read or mutate the object, interpret the flag, or call anything.
/// Deliberately exposes the unchanged r0 as a pointer return rather than
/// Ghidra's void signature; the flag's meaning and concrete class are unknown.
/// Verified ARM codegen retains a real exported symbol: LLVM emits
/// `push {fp,lr}; mov fp,sp; pop {fp,pc}` instead of the stock `bx lr`.
/// This adds a frame but leaves r0 and object storage untouched. Host tests
/// and a standalone actual-source executable verify pointer pass-through
/// and unchanged storage; no on-device execution is claimed.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub extern "C" fn singleton_state_noop(singleton: *mut u8, _flag: u32) -> *mut u8 {
    singleton
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    pub(crate) static ACCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct SingletonStateBaseReset;

    impl Drop for SingletonStateBaseReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(HOST_SINGLETON_STATE_BASE)
                    .write(core::ptr::null_mut());
            }
        }
    }

    fn install_base_slot() -> MutexGuard<'static, ()> {
        let guard = ACCESS_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            core::ptr::addr_of_mut!(HOST_SINGLETON_STATE_BASE)
                .write(core::ptr::null_mut());
        }
        guard
    }

    #[test]
    fn noop_preserves_null_and_unreadable_pointer_values_for_all_flag_bits() {
        for singleton in [core::ptr::null_mut(), 1usize as *mut u8, usize::MAX as *mut u8] {
            for flag in [0, 1, 0x8000_0000, u32::MAX] {
                assert_eq!(singleton_state_noop(singleton, flag), singleton);
            }
        }
    }

    #[test]
    fn noop_leaves_singleton_storage_unchanged() {
        let mut singleton = [0x1234_5678u32, 0, u32::MAX, 0x8765_4321];
        let original = singleton;
        let pointer = singleton.as_mut_ptr().cast::<u8>();
        assert_eq!(singleton_state_noop(pointer, 1), pointer);
        assert_eq!(singleton, original);
    }

    #[test]
    fn loads_the_current_global_base_slot() {
        let _guard = install_base_slot();
        let _reset = SingletonStateBaseReset;
        let mut first = [0u32; 7];
        let mut second = [0u32; 7];

        unsafe {
            core::ptr::addr_of_mut!(HOST_SINGLETON_STATE_BASE)
                .write(first.as_mut_ptr() as *mut u8);
            assert_eq!(singleton_state_base_get(), first.as_mut_ptr() as *mut u8);

            core::ptr::addr_of_mut!(HOST_SINGLETON_STATE_BASE)
                .write(second.as_mut_ptr() as *mut u8);
            assert_eq!(singleton_state_base_get(), second.as_mut_ptr() as *mut u8);
        }
    }

    #[test]
    fn state_get_loads_the_base_objects_raw_word_at_offset_0x18() {
        let _guard = install_base_slot();
        let _reset = SingletonStateBaseReset;
        let mut singleton = [0u32; 7];
        singleton[6] = 0x7654_3210;

        unsafe {
            core::ptr::addr_of_mut!(HOST_SINGLETON_STATE_BASE)
                .write(singleton.as_mut_ptr() as *mut u8);
            assert_eq!(singleton_state_get(), 0x7654_3210);
        }
    }
}
