//! `app_object_init` — original: `FUN_0811000c` @ 0x0811000c (52 bytes).
//!
//! Initializes the 0x30-byte application-object base used by the lazy global
//! accessor at `FUN_0810fa30`. It installs vtable `0x0898165c`, clears the
//! sparse scalar fields at +0x04, +0x08, +0x0c, and +0x20, and delegates the
//! embedded drain state at +0x10 to `FUN_08271cec`. The final two words at
//! +0x28 and +0x2c are cleared relative to the pointer returned by that
//! constructor after subtracting 0x10, exactly as the stock `sub r0, r0,
//! #16` does. It deliberately leaves all other bytes unchanged.
//!
//! Sources: `ipod-decomp/decomp/c/010/0811000c_FUN_0811000c.c`,
//! `ipod-decomp/decomp/c/026/08271cec_FUN_08271cec.c`, and the instruction
//! sequence at 0x0811000c in `ipod-decomp/decomp/osos.asm`.

/// Byte length of the application object initialized by [`app_object_init`].
pub const APP_OBJECT_SIZE: usize = 0x30;

const VTABLE: usize = 0x00;
const FIRST_LINK: usize = 0x04;
const SECOND_LINK: usize = 0x08;
const ENABLED: usize = 0x0c;
const DRAIN_STATE: usize = 0x10;
const STATE_WORD: usize = 0x20;
const TAIL_FIRST: usize = 0x28;
const TAIL_SECOND: usize = 0x2c;

/// Vtable literal loaded by the retail initializer from 0x08110040.
pub const APP_OBJECT_VTABLE: u32 = 0x0898_165c;

/// Constructor for the 0x18-byte embedded drain state at +0x10
/// (`FUN_08271cec`). It returns the same embedded-object base in retailOS.
pub type DrainStateConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

/// External construction operation used by [`app_object_init`].
#[derive(Clone, Copy)]
pub struct AppObjectOps {
    pub construct_drain_state: DrainStateConstruct,
}

// The drain-state constructor is not ported as a callable standalone symbol.
// A target integration must provide it before this initializer is hooked.
unsafe extern "C" fn missing_drain_state_construct(_state: *mut u8) -> *mut u8 {
    panic!("app_object_init requires drain-state constructor 0x08271cec")
}

/// Replace before first target use; focused host tests install a recorder.
pub static mut APP_OBJECT_OPS: AppObjectOps = AppObjectOps {
    construct_drain_state: missing_drain_state_construct,
};

#[inline(always)]
unsafe fn app_object_ops() -> AppObjectOps {
    core::ptr::read_volatile(core::ptr::addr_of!(APP_OBJECT_OPS))
}

/// app_object_init — original: `FUN_0811000c` @ 0x0811000c (52 bytes).
///
/// Initializes an already allocated application object. There is no NULL
/// guard or whole-object clear. Although the embedded constructor conventionally
/// returns `this + 0x10`, stores after that call derive their base from its
/// returned pointer; preserving that detail is important for ABI fidelity.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_object_init(this: *mut u8) {
    (this.add(VTABLE) as *mut u32).write(APP_OBJECT_VTABLE);
    (this.add(SECOND_LINK) as *mut u32).write(0);

    let drain_state = (app_object_ops().construct_drain_state)(this.add(DRAIN_STATE));
    let returned_base = drain_state.sub(DRAIN_STATE);

    (returned_base.add(TAIL_FIRST) as *mut u32).write(0);
    (returned_base.add(TAIL_SECOND) as *mut u32).write(0);
    (returned_base.add(FIRST_LINK) as *mut u32).write(0);
    returned_base.add(ENABLED).write(0);
    (returned_base.add(STATE_WORD) as *mut u32).write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CONSTRUCT_ARG: usize = 0;
    static mut CONSTRUCT_RETURN: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn record_drain_state(state: *mut u8) -> *mut u8 {
        CONSTRUCT_ARG = state as usize;
        CONSTRUCT_RETURN
    }

    struct RestoreOps;

    impl Drop for RestoreOps {
        fn drop(&mut self) {
            unsafe {
                APP_OBJECT_OPS = AppObjectOps {
                    construct_drain_state: missing_drain_state_construct,
                };
            }
        }
    }

    fn mock() -> (MutexGuard<'static, ()>, RestoreOps) {
        let lock = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            CONSTRUCT_ARG = 0;
            CONSTRUCT_RETURN = core::ptr::null_mut();
            APP_OBJECT_OPS = AppObjectOps {
                construct_drain_state: record_drain_state,
            };
        }
        (lock, RestoreOps)
    }

    #[test]
    fn it_constructs_the_embedded_drain_state_at_plus_0x10() {
        let (_lock, _restore) = mock();
        let mut object = [0xa5u8; APP_OBJECT_SIZE];
        let base = object.as_mut_ptr();
        unsafe {
            CONSTRUCT_RETURN = base.add(DRAIN_STATE);
            app_object_init(base);
            assert_eq!(CONSTRUCT_ARG, base.add(DRAIN_STATE) as usize);
        }
    }

    #[test]
    fn it_writes_exactly_the_stock_sparse_initial_state() {
        let (_lock, _restore) = mock();
        let mut object = [0xa5u8; APP_OBJECT_SIZE];
        let base = object.as_mut_ptr();
        unsafe {
            CONSTRUCT_RETURN = base.add(DRAIN_STATE);
            app_object_init(base);
        }

        let mut expected = [0xa5u8; APP_OBJECT_SIZE];
        expected[VTABLE..VTABLE + 4].copy_from_slice(&APP_OBJECT_VTABLE.to_le_bytes());
        expected[FIRST_LINK..FIRST_LINK + 4].fill(0);
        expected[SECOND_LINK..SECOND_LINK + 4].fill(0);
        expected[ENABLED] = 0;
        expected[STATE_WORD..STATE_WORD + 4].fill(0);
        expected[TAIL_FIRST..TAIL_FIRST + 4].fill(0);
        expected[TAIL_SECOND..TAIL_SECOND + 4].fill(0);
        assert_eq!(object, expected);
    }

    #[test]
    fn post_constructor_stores_follow_its_returned_base() {
        let (_lock, _restore) = mock();
        // The stock body subtracts 0x10 from r0 after the call; this arena
        // makes a deliberately shifted return observable without writing out
        // of bounds.
        let mut arena = [0xa5u8; APP_OBJECT_SIZE + DRAIN_STATE];
        let input_base = unsafe { arena.as_mut_ptr().add(DRAIN_STATE) };
        let returned_base = arena.as_mut_ptr();
        unsafe {
            CONSTRUCT_RETURN = returned_base.add(DRAIN_STATE);
            app_object_init(input_base);
        }

        assert_eq!(&arena[TAIL_FIRST..TAIL_FIRST + 4], &[0; 4]);
        assert_eq!(&arena[TAIL_SECOND..TAIL_SECOND + 4], &[0; 4]);
        assert_eq!(&arena[FIRST_LINK..FIRST_LINK + 4], &[0; 4]);
        assert_eq!(arena[ENABLED], 0);
        assert_eq!(&arena[STATE_WORD..STATE_WORD + 4], &[0; 4]);
        // The pre-call stores still target the incoming object.
        assert_eq!(
            &arena[DRAIN_STATE + VTABLE..DRAIN_STATE + VTABLE + 4],
            &APP_OBJECT_VTABLE.to_le_bytes()
        );
    }
}
