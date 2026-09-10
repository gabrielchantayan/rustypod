//! `range_state_construct` — original: `FUN_081f7278` @ **0x081f7278**.
//!
//! The raw extent is exactly **88 bytes**, `0x081f7278..0x081f72d0`: the next
//! separately linked constructor starts at `0x081f72d0`. Decoding every ARM
//! `B`/`BL` word in `osos.dec` finds **11 direct call sites**, all plain,
//! unconditional `bl`; there are no predicated calls or tail branches.
//!
//! # Algorithm
//!
//! Initializes the fixed portions of a 16-word range state: word 0 becomes
//! zero, word 1 becomes the invalid `u32::MAX` sentinel, and four two-word
//! bucket records at words 5–12 are zeroed. Words 2–4 and 13–15 are left
//! untouched. When `initial_value` is nonzero, the constructor forwards the
//! receiver, `initial_value`, and its third ABI argument to the range-state
//! reconfiguration routine at `0x081f7194`; the incoming third argument is
//! real even though Ghidra omitted it from this function's signature.
//!
//! On firmware builds the reconfiguration call reaches the retained retail
//! routine directly. Host builds deliberately use an inert default because
//! that routine is not yet ported; unit tests replace it to prove the call
//! gate and ABI forwarding.

/// Fixed 16-word storage initialized by [`range_state_construct`].
///
/// The named fields retain the target's word layout on both the 32-bit
/// firmware and 64-bit hosts. `header_words` and `tail_words` are deliberately
/// not written by this constructor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeState {
    pub current_value: u32,
    pub resolution: u32,
    pub header_words: [u32; 3],
    pub bucket_bounds: [[u32; 2]; 4],
    pub tail_words: [u32; 3],
}

type RangeStateConfigure = unsafe extern "C" fn(*mut RangeState, *const u32, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn configure_range_state(state: *mut RangeState, initial_value: *const u32, resolution: u32) {
    let configure: RangeStateConfigure = core::mem::transmute(0x081f_7194usize);
    configure(state, initial_value, resolution);
}

#[cfg(all(not(target_os = "none"), not(test)))]
unsafe fn configure_range_state(_state: *mut RangeState, _initial_value: *const u32, _resolution: u32) {}

#[cfg(test)]
unsafe extern "C" fn inert_range_state_configure(
    _state: *mut RangeState,
    _initial_value: *const u32,
    _resolution: u32,
) {}

#[cfg(test)]
static mut RANGE_STATE_CONFIGURE: RangeStateConfigure = inert_range_state_configure;

#[cfg(test)]
unsafe fn configure_range_state(state: *mut RangeState, initial_value: *const u32, resolution: u32) {
    RANGE_STATE_CONFIGURE(state, initial_value, resolution);
}

/// Constructs the fixed portion of a range state and returns `state`.
///
/// # Safety
///
/// `state` must be non-NULL, four-byte aligned, and writable for 16 `u32`
/// words. `initial_value` must be non-NULL and four-byte aligned; the retail
/// routine reads it unconditionally before deciding whether to reconfigure.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.range_state_construct")]
#[inline(never)]
pub unsafe extern "C" fn range_state_construct(
    state: *mut RangeState,
    initial_value: *const u32,
    resolution: u32,
) -> *mut RangeState {
    (*state).current_value = 0;
    (*state).resolution = u32::MAX;
    (*state).bucket_bounds = [[0; 2]; 4];

    if initial_value.read() != 0 {
        configure_range_state(state, initial_value, resolution);
    }

    state
}

#[cfg(test)]
mod tests {
    use super::{inert_range_state_configure, range_state_construct, RangeState, RANGE_STATE_CONFIGURE};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CONFIGURE_CALLS: u32 = 0;
    static mut CONFIGURE_STATE: Option<RangeState> = None;
    static mut CONFIGURE_VALUE: *const u32 = core::ptr::null();
    static mut CONFIGURE_RESOLUTION: u32 = 0;

    unsafe extern "C" fn record_configure(
        state: *mut RangeState,
        initial_value: *const u32,
        resolution: u32,
    ) {
        CONFIGURE_CALLS += 1;
        CONFIGURE_STATE = Some(*state);
        CONFIGURE_VALUE = initial_value;
        CONFIGURE_RESOLUTION = resolution;
    }

    fn sentinel_state() -> RangeState {
        RangeState {
            current_value: 0x1111_1111,
            resolution: 0x2222_2222,
            header_words: [0x3333_3333, 0x4444_4444, 0x5555_5555],
            bucket_bounds: [[0x6666_6666, 0x7777_7777]; 4],
            tail_words: [0x8888_8888, 0x9999_9999, 0xaaaa_aaaa],
        }
    }

    #[test]
    fn zero_initial_value_skips_configuration_and_preserves_unwritten_words() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CONFIGURE_CALLS = 0;
            RANGE_STATE_CONFIGURE = record_configure;
        }
        let mut state = sentinel_state();
        let initial_value = 0;

        let returned = unsafe { range_state_construct(&mut state, &initial_value, 0x10) };

        unsafe { RANGE_STATE_CONFIGURE = inert_range_state_configure; }
        assert_eq!(returned, &mut state as *mut RangeState);
        assert_eq!(unsafe { CONFIGURE_CALLS }, 0);
        assert_eq!(state.current_value, 0);
        assert_eq!(state.resolution, u32::MAX);
        assert_eq!(state.header_words, [0x3333_3333, 0x4444_4444, 0x5555_5555]);
        assert_eq!(state.bucket_bounds, [[0; 2]; 4]);
        assert_eq!(state.tail_words, [0x8888_8888, 0x9999_9999, 0xaaaa_aaaa]);
    }

    #[test]
    fn nonzero_initial_value_configures_after_fixed_fields_are_initialized() {
        let _guard = TEST_LOCK.lock();
        unsafe {
            CONFIGURE_CALLS = 0;
            CONFIGURE_STATE = None;
            CONFIGURE_VALUE = core::ptr::null();
            CONFIGURE_RESOLUTION = 0;
            RANGE_STATE_CONFIGURE = record_configure;
        }
        let mut state = sentinel_state();
        let initial_value = 0x1234_5678;

        let returned = unsafe { range_state_construct(&mut state, &initial_value, 7) };

        let (calls, observed_state, observed_value, observed_resolution) = unsafe {
            let result = (CONFIGURE_CALLS, CONFIGURE_STATE, CONFIGURE_VALUE, CONFIGURE_RESOLUTION);
            RANGE_STATE_CONFIGURE = inert_range_state_configure;
            result
        };
        assert_eq!(returned, &mut state as *mut RangeState);
        assert_eq!(calls, 1);
        assert_eq!(observed_value, &initial_value as *const u32);
        assert_eq!(observed_resolution, 7);
        assert_eq!(observed_state.unwrap().current_value, 0);
        assert_eq!(observed_state.unwrap().resolution, u32::MAX);
        assert_eq!(observed_state.unwrap().bucket_bounds, [[0; 2]; 4]);
        assert_eq!(state.header_words, [0x3333_3333, 0x4444_4444, 0x5555_5555]);
        assert_eq!(state.tail_words, [0x8888_8888, 0x9999_9999, 0xaaaa_aaaa]);
    }
}
