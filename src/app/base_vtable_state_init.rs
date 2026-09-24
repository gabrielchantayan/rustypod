//! `base_vtable_state_init` — original: `FUN_081215c8` @ `0x081215c8`.
//!
//! Raw A32 establishes a 36-byte true extent: eight instruction words through
//! `bx lr` at `0x081215e4`, followed by the `0x08982fc4` vtable literal at
//! `0x081215e8`; the separately linked next function begins at `0x081215ec`.
//! Independent raw decoding finds three inbound plain, unconditional `bl` call
//! sites (`0x08167448`, `0x0818dcd0`, and `0x0820c800`), with no predicated
//! `bl` forms.
//!
//! # Algorithm
//!
//! Installs an unrecovered base vtable, clears the first state word, and sets
//! the final two state words to the all-ones sentinel. It returns the caller's
//! storage unchanged; each known direct caller immediately replaces the base
//! vtable with a derived vtable.
//!
//! # Deliberate deviations
//!
//! The concrete class identity is not established. `BaseVtableState` names
//! only the verified four-word target layout and initialization behavior.

pub const BASE_VTABLE_STATE_VTABLE: u32 = 0x0898_2fc4;
pub const BASE_VTABLE_STATE_SIZE: usize = 0x10;

/// The four-word target-layout state initialized by [`base_vtable_state_init`].
#[repr(C)]
pub struct BaseVtableState {
    pub vtable: u32,
    pub state: u32,
    pub first_sentinel: u32,
    pub second_sentinel: u32,
}

const _: [u8; BASE_VTABLE_STATE_SIZE] = [0; core::mem::size_of::<BaseVtableState>()];

/// Initializes base state in caller-provided storage and returns `storage`.
///
/// # Safety
///
/// `storage` must be a valid, word-aligned pointer to at least
/// [`BASE_VTABLE_STATE_SIZE`] writable bytes. The retail code performs no NULL
/// or bounds checks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn base_vtable_state_init(storage: *mut BaseVtableState) -> *mut BaseVtableState {
    unsafe {
        (*storage).vtable = BASE_VTABLE_STATE_VTABLE;
        (*storage).state = 0;
        (*storage).first_sentinel = u32::MAX;
        (*storage).second_sentinel = u32::MAX;
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_each_word_and_returns_the_input_storage() {
        let mut state = BaseVtableState {
            vtable: 0,
            state: 0x1111_1111,
            first_sentinel: 0x2222_2222,
            second_sentinel: 0x3333_3333,
        };

        let result = unsafe { base_vtable_state_init(&mut state) };

        assert!(core::ptr::eq(result, &mut state));
        assert_eq!(state.vtable, BASE_VTABLE_STATE_VTABLE);
        assert_eq!(state.state, 0);
        assert_eq!(state.first_sentinel, u32::MAX);
        assert_eq!(state.second_sentinel, u32::MAX);
    }

    #[test]
    fn overwrites_all_preexisting_state_words() {
        let mut state = BaseVtableState {
            vtable: u32::MAX,
            state: u32::MAX,
            first_sentinel: 0,
            second_sentinel: 0,
        };

        unsafe { base_vtable_state_init(&mut state) };

        assert_eq!([state.vtable, state.state, state.first_sentinel, state.second_sentinel],
            [BASE_VTABLE_STATE_VTABLE, 0, u32::MAX, u32::MAX]);
    }
}
