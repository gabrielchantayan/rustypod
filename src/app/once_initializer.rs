//! `initialize_once` — original: `FUN_081ded74` @ **0x081ded74**
//! (**68 bytes** of instructions, `0x081ded74..0x081dedb4`; its two-word
//! literal pool is `0x081dedb8..0x081dedbc`, and the next separately linked
//! function starts at `0x081dedc0`).
//!
//! A decoded scan of every ARM B/BL word in `osos.dec` finds **10 direct BL
//! callers**, all unconditional (`cond = AL`), and **0 predicated BL forms**.
//! The function makes one direct BL to the unported `FUN_080e9cbc`.
//!
//! Algorithm: if `state + 0x25` is zero, invoke the fixed seven-argument
//! initializer and then store one at that byte. Any nonzero byte skips the
//! invocation and remains unchanged. The raw first initializer argument,
//! `0x083ec9d0`, does not decode as a valid function entry: its first
//! instruction is a `bmi` that depends on incoming flags. It is therefore
//! retained as an opaque argument rather than assigned a callee identity.
//!
//! Deliberate deviation: `FUN_080e9cbc` is not ported. Target builds call its
//! fixed retailOS address; host builds use a replaceable inert seam so tests
//! can prove the guard and the exact argument sequence.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

const RETAIL_ONCE_INITIALIZER: usize = 0x080e_9cbc;
const INITIALIZER_ARGS: [u32; 7] = [0x083e_c9d0, 0x081d_41fc, 0, 0x20, 0x8000, 1, 0x32];

/// Target layout through the byte gate at `+0x25`.
#[repr(C)]
pub struct OnceInitializationState {
    pub unresolved_00_24: [u8; 0x25],
    pub initialized: u8,
}

/// ABI of the unported fixed initializer `FUN_080e9cbc`.
pub type OnceInitializer = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn invoke_once_initializer() {
    let initializer: OnceInitializer = core::mem::transmute(RETAIL_ONCE_INITIALIZER);
    initializer(
        INITIALIZER_ARGS[0],
        INITIALIZER_ARGS[1],
        INITIALIZER_ARGS[2],
        INITIALIZER_ARGS[3],
        INITIALIZER_ARGS[4],
        INITIALIZER_ARGS[5],
        INITIALIZER_ARGS[6],
    );
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_once_initializer(
    _arg0: u32,
    _arg1: u32,
    _arg2: u32,
    _arg3: u32,
    _arg4: u32,
    _arg5: u32,
    _arg6: u32,
) {}

/// Host seam for the unported fixed initializer.
#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct OnceInitializerOps {
    pub invoke: OnceInitializer,
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_ONCE_INITIALIZER_OPS: OnceInitializerOps = OnceInitializerOps {
    invoke: missing_once_initializer,
};

#[cfg(not(target_os = "none"))]
pub static mut ONCE_INITIALIZER_OPS: OnceInitializerOps = DEFAULT_ONCE_INITIALIZER_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn invoke_once_initializer() {
    let initializer = core::ptr::read_volatile(addr_of!(ONCE_INITIALIZER_OPS.invoke));
    initializer(
        INITIALIZER_ARGS[0],
        INITIALIZER_ARGS[1],
        INITIALIZER_ARGS[2],
        INITIALIZER_ARGS[3],
        INITIALIZER_ARGS[4],
        INITIALIZER_ARGS[5],
        INITIALIZER_ARGS[6],
    );
}

/// Invokes the fixed initializer once for a state object.
///
/// # Safety
///
/// `state` must point to at least `0x26` readable and writable bytes using
/// [`OnceInitializationState`]'s target layout.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn initialize_once(state: *mut OnceInitializationState) {
    if (*state).initialized == 0 {
        invoke_once_initializer();
        (*state).initialized = 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL_COUNT: usize = 0;
    static mut CALL_ARGS: [u32; 7] = [0; 7];

    unsafe extern "C" fn recording_initializer(
        arg0: u32,
        arg1: u32,
        arg2: u32,
        arg3: u32,
        arg4: u32,
        arg5: u32,
        arg6: u32,
    ) {
        CALL_COUNT += 1;
        CALL_ARGS = [arg0, arg1, arg2, arg3, arg4, arg5, arg6];
    }

    unsafe fn reset() {
        CALL_COUNT = 0;
        CALL_ARGS = [0; 7];
        ONCE_INITIALIZER_OPS = OnceInitializerOps {
            invoke: recording_initializer,
        };
    }

    #[test]
    fn zero_gate_invokes_initializer_with_fixed_arguments_then_sets_gate() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut state = OnceInitializationState {
            unresolved_00_24: [0; 0x25],
            initialized: 0,
        };

        unsafe {
            reset();
            initialize_once(addr_of_mut!(state));
            initialize_once(addr_of_mut!(state));
            assert_eq!(CALL_COUNT, 1);
            assert_eq!(CALL_ARGS, INITIALIZER_ARGS);
        }
        assert_eq!(state.initialized, 1);
    }

    #[test]
    fn nonzero_gate_skips_initializer_and_preserves_byte() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut state = OnceInitializationState {
            unresolved_00_24: [0; 0x25],
            initialized: 0xa5,
        };

        unsafe {
            reset();
            initialize_once(addr_of_mut!(state));
            assert_eq!(CALL_COUNT, 0);
        }
        assert_eq!(state.initialized, 0xa5);
    }
}
