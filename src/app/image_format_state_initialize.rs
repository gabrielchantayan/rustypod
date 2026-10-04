//! `image_format_state_initialize` — `FUN_082201f8` @ 0x082201f8.
//! True extent: 164 bytes, 0x082201f8..0x0822029c; the next function
//! starts with `mov ip,r0`. Raw decoding counts eight plain outbound BLs
//! and one predicated BLNE; whole-image decoding finds two plain inbound
//! BLs (0x08142b64, 0x0817db60), zero predicated inbound BLs.
//!
//! Builds a 165-word descriptor-slots object with kinds 15 and 16, calls
//! the state initializer with position 2, then validates position 2 only
//! on initialization success. Validation success resets words +0x89c and
//! +0x8a0 to -1 and writes the owner at +0x20. Returns the exact validation
//! result (or zero on initialization failure), and drops the temporary.
//!
//! Deviations: the unported three-argument initializer at 0x0822aa58 is
//! a fixed-address ARM seam, injectable on hosts. Unwritten temporary words
//! remain uninitialized, as in stock; the empty destructor may be optimized
//! away. Host invocation requires installing the initializer seam.

use crate::app::image_format::image_format_descriptor_for_kind;
use crate::app::image_format_descriptor_slot::image_format_descriptor_slot_set;
use crate::app::image_format_descriptor_slots_initialize::image_format_descriptor_slots_initialize;
use crate::app::mode_selected_position_validate::mode_selected_position_validate;
use crate::cxx::empty_destructor_1d6030::empty_destructor_1d6030;
use crate::util::object_set_word_0x20::object_set_word_0x20;

pub type InitializeDescriptorState = unsafe extern "C" fn(*mut u8, *const u32, u32) -> u32;
type ValidatePosition = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_initializer(_: *mut u8, _: *const u32, _: u32) -> u32 {
    panic!("install INITIALIZE_DESCRIPTOR_STATE before host invocation")
}

/// Host-only retail initializer seam; callers must serialize replacement/use.
#[cfg(not(target_arch = "arm"))]
pub static mut INITIALIZE_DESCRIPTOR_STATE: InitializeDescriptorState = missing_initializer;

#[inline(always)]
unsafe fn initializer() -> InitializeDescriptorState {
    #[cfg(target_arch = "arm")]
    { core::mem::transmute(0x0822_aa58usize) }
    #[cfg(not(target_arch = "arm"))]
    { core::ptr::addr_of!(INITIALIZE_DESCRIPTOR_STATE).read_volatile() }
}

/// Initializes image-format state and binds its owner on success.
///
/// # Safety
/// `state` must satisfy the retail initializer and validator contracts, with
/// aligned writable words through +0x8a0. `owner` is a target-width opaque
/// value. Host callers must install a valid initializer seam before use.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn image_format_state_initialize(state: *mut u8, owner: u32) -> u32 {
    initialize_with(state, owner, initializer(), mode_selected_position_validate)
}

#[inline(always)]
unsafe fn initialize_with(state: *mut u8, owner: u32, initialize: InitializeDescriptorState, validate: ValidatePosition) -> u32 {
    let mut slots = core::mem::MaybeUninit::<[u32; 165]>::uninit();
    let slots = slots.as_mut_ptr().cast::<u32>();
    let mut descriptor = core::mem::MaybeUninit::<[u32; 8]>::uninit();
    let descriptor = descriptor.as_mut_ptr().cast::<u8>();
    image_format_descriptor_slots_initialize(slots);
    image_format_descriptor_for_kind(descriptor, 15);
    image_format_descriptor_slot_set(slots, 15, descriptor);
    image_format_descriptor_for_kind(descriptor, 16);
    image_format_descriptor_slot_set(slots, 16, descriptor);
    let mut result = initialize(state, slots, 2);
    if result != 0 {
        result = validate(state, 2);
        if result != 0 {
            state.add(0x89c).cast::<u32>().write(u32::MAX);
            state.add(0x8a0).cast::<u32>().write(u32::MAX);
            object_set_word_0x20(state, owner);
        }
    }
    empty_destructor_1d6030(slots.cast());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn initialize(state: *mut u8, slots: *const u32, position: u32) -> u32 {
        assert_eq!(position, 2);
        assert_eq!(slots.add(164).read(), 2);
        assert_eq!(slots.add(163).read(), u32::MAX);
        for (kind, sequence) in [(15, 0), (16, 1)] {
            let mut expected = [0u32; 8];
            image_format_descriptor_for_kind(expected.as_mut_ptr().cast(), kind);
            let record = slots.add(9 + kind as usize * 9);
            assert_eq!(record.read(), sequence);
            assert_eq!(core::slice::from_raw_parts(record.add(1), 8), &expected);
        }
        state.cast::<u32>().read()
    }

    unsafe extern "C" fn validate(state: *mut u8, _: u32) -> u32 {
        // Observable validator side effect proves the failed initializer skips it.
        state.add(12).cast::<u32>().write(0x1234);
        state.add(4).cast::<u32>().read()
    }

    #[test]
    fn failure_paths_preserve_owner_and_cached_words() {
        for (initial, valid, side_effect) in [(0, 7, 0xa5a5_a5a5), (1, 0, 0x1234)] {
            let mut state = [0xa5a5_a5a5u32; 0x8a4 / 4];
            state[0] = initial;
            state[1] = valid;
            let result = unsafe { initialize_with(state.as_mut_ptr().cast(), 0x8877, initialize, validate) };
            assert_eq!(result, 0);
            assert_eq!(state[3], side_effect);
            assert_eq!(state[8], 0xa5a5_a5a5);
            assert_eq!(&state[0x89c / 4..], &[0xa5a5_a5a5; 2]);
        }
    }

    #[test]
    fn success_resets_caches_and_preserves_nonboolean_result() {
        let mut state = [0x1122_3344u32; 0x8a4 / 4];
        state[0] = 0x8000_0000;
        state[1] = 7;
        let result = unsafe { initialize_with(state.as_mut_ptr().cast(), u32::MAX, initialize, validate) };
        assert_eq!(result, 7);
        assert_eq!(state[8], u32::MAX);
        assert_eq!(&state[0x89c / 4..], &[u32::MAX; 2]);
        assert_eq!(state[3], 0x1234);
        assert_eq!(state[9], 0x1122_3344);
        assert_eq!(state[0x898 / 4], 0x1122_3344);
    }
}
