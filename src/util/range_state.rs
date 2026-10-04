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

/// `range_state_copy_construct` — `FUN_081f71ec` @ `0x081f71ec`.
///
/// Raw extent: **140 bytes**, `0x081f71ec..0x081f7278`, ending with
/// `pop {r4-r6,pc}` before the next constructor. Whole-image ARM decoding
/// finds two inbound plain BLs (0x081b4eec and 0x081b4f00), no predicated
/// inbound BLs; the body has one plain BL at 0x081f7214, no predicated BLs.
///
/// Copies the first two words, ten packed header bytes at +8, four pairs
/// of bucket bounds, then three tail words. Destination bytes +18 and +19
/// are deliberately untouched. Returns the original destination pointer.
///
/// Deviation: the verified 0x08037db0 -> 0x22000020 IRAM mirror veneer is
/// replaced by the existing Rust `__rt_memcpy` port; its return is ignored.
/// Word pairs are read before either store, matching the retail sequence.
///
/// # Safety
///
/// Both pointers must be four-byte aligned and valid for 64 bytes of
/// initialized storage; destination must be writable. They may be equal,
/// but otherwise must not overlap. The packed header is copied as bytes,
/// not interpreted as host pointers or widened fields.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_state_copy_construct(
    destination: *mut RangeState,
    source: *const RangeState,
) -> *mut RangeState {
    let dst = destination.cast::<u32>();
    let src = source.cast::<u32>();
    dst.write(src.read());
    dst.add(1).write(src.add(1).read());
    crate::libc::rt_memcpy::__rt_memcpy(dst.add(2).cast(), src.add(2).cast(), 10);
    for word in [5, 7, 9, 11] {
        let first = src.add(word).read();
        let second = src.add(word + 1).read();
        dst.add(word).write(first);
        dst.add(word + 1).write(second);
    }
    for word in 13..16 {
        dst.add(word).write(src.add(word).read());
    }
    destination
}

#[cfg(test)]
mod copy_tests {
    use super::{range_state_copy_construct, RangeState};

    #[test]
    fn copies_fields_without_copying_header_padding_or_touching_neighbors() {
        for seed in [0u8, 0x7f, 0xff] {
            let mut source = [0u32; 16];
            let mut guarded = [0xa5a5_a5a5u32; 18];
            let source_bytes = unsafe {
                core::slice::from_raw_parts_mut(source.as_mut_ptr().cast::<u8>(), 64)
            };
            for (index, byte) in source_bytes.iter_mut().enumerate() {
                *byte = seed.wrapping_add((index as u8).wrapping_mul(37));
            }
            let before = source;
            let destination = unsafe { guarded.as_mut_ptr().add(1).cast::<RangeState>() };
            let returned = unsafe {
                range_state_copy_construct(destination, source.as_ptr().cast())
            };
            assert_eq!(returned, destination);
            assert_eq!(source, before);
            assert_eq!(guarded[0], 0xa5a5_a5a5);
            assert_eq!(guarded[17], 0xa5a5_a5a5);
            let actual = unsafe { core::slice::from_raw_parts(destination.cast::<u8>(), 64) };
            let original = unsafe { core::slice::from_raw_parts(source.as_ptr().cast::<u8>(), 64) };
            let mut expected = [0xa5u8; 64];
            expected[..18].copy_from_slice(&original[..18]);
            expected[20..].copy_from_slice(&original[20..]);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn self_copy_preserves_every_byte() {
        let mut words = core::array::from_fn::<_, 16, _>(|i| {
            (i as u32).wrapping_mul(0x1234_5679) ^ 0xdead_beef
        });
        let before = words;
        let state = words.as_mut_ptr().cast::<RangeState>();
        assert_eq!(unsafe { range_state_copy_construct(state, state) }, state);
        assert_eq!(words, before);
    }
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
