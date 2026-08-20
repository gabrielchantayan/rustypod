//! `buffer_state_is_full` — original: `FUN_0807595c` @ `0x0807595c`
//! (36 bytes, including the 4-byte global literal at `0x08075980`).
//!
//! The firmware owns two adjacent 0x48-byte buffer-state records at
//! `0x08b1c858`. Each has sixteen u32 entry words followed by an item count
//! at +0x40 and a capacity at +0x44. The surrounding buffer code initializes
//! each capacity to 16, appends/removes entries while changing the item count,
//! and uses this predicate before enqueueing. The selector chooses the second
//! record only when it is exactly one; every other u32 value addresses the
//! first. It returns the ARM equality result (one or zero), so the predicate
//! is true when the selected buffer is full.
//!
//! `BUFFER_STATES` is the crate's model of the fixed firmware BSS object, not
//! storage owned by this function. Future ports that initialize or mutate the
//! same target global must use this seam rather than introduce another copy.

/// One 0x48-byte state record in the target's paired buffer global.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BufferState {
    entries: [u32; 16],
    item_count: u32,
    capacity: u32,
}

const EMPTY_BUFFER_STATE: BufferState = BufferState {
    entries: [0; 16],
    item_count: 0,
    capacity: 0,
};

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x48] = [0; core::mem::size_of::<BufferState>()];

/// Crate model of the two target records at `0x08b1c858` and `+0x48`.
///
/// The firmware's initializer (`FUN_08090c48`) clears both records and sets
/// their +0x44 capacity words to 16. It is not ported here; callers that wire
/// it in must initialize this single model before using it.
pub static mut BUFFER_STATES: [BufferState; 2] = [EMPTY_BUFFER_STATE; 2];

/// buffer_state_is_full — original: `FUN_0807595c` @ `0x0807595c` (36 bytes).
///
/// Selects buffer state zero except for selector exactly one, which selects
/// state one. Returns 1 when that state's item count equals its capacity and
/// 0 otherwise, matching the original `cmp`/`movne`/`moveq` return ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffer_state_is_full(selector: u32) -> u32 {
    let first = core::ptr::addr_of!(BUFFER_STATES).cast::<BufferState>();
    let state = if selector == 1 { first.add(1) } else { first };
    // The BSS record is mutable outside this single port; volatile reads keep
    // the target loads observable instead of folding the zero initializer.
    let item_count = core::ptr::read_volatile(core::ptr::addr_of!((*state).item_count));
    let capacity = core::ptr::read_volatile(core::ptr::addr_of!((*state).capacity));
    u32::from(item_count == capacity)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static BUFFER_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn set_state(slot: usize, item_count: u32, capacity: u32) {
        let state = core::ptr::addr_of_mut!(BUFFER_STATES).cast::<BufferState>().add(slot);
        (*state).item_count = item_count;
        (*state).capacity = capacity;
    }

    #[test]
    fn selector_one_uses_only_the_second_buffer() {
        let _guard = BUFFER_STATE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            set_state(0, 3, 16);
            set_state(1, 16, 16);
            assert_eq!(buffer_state_is_full(0), 0, "selector zero uses state zero");
            assert_eq!(buffer_state_is_full(1), 1, "selector one uses state one");
        }
    }

    #[test]
    fn every_non_one_selector_uses_the_first_buffer() {
        let _guard = BUFFER_STATE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        unsafe {
            set_state(0, 7, 7);
            set_state(1, 7, 8);
            for selector in [0u32, 2, 3, 0x8000_0000, u32::MAX] {
                assert_eq!(
                    buffer_state_is_full(selector),
                    1,
                    "selector {selector:#010x} must share state zero"
                );
            }
        }
    }

    #[test]
    fn returns_the_exact_equality_result_for_both_selected_records() {
        let _guard = BUFFER_STATE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for &(item_count, capacity, expected) in &[
            (0u32, 0u32, 1u32),
            (1, 1, 1),
            (u32::MAX, u32::MAX, 1),
            (0, 1, 0),
            (1, 0, 0),
            (u32::MAX, u32::MAX - 1, 0),
        ] {
            unsafe {
                set_state(0, item_count, capacity);
                set_state(1, item_count, capacity);
                assert_eq!(buffer_state_is_full(0), expected, "state zero: {item_count:#x}, {capacity:#x}");
                assert_eq!(buffer_state_is_full(1), expected, "state one: {item_count:#x}, {capacity:#x}");
            }
        }
    }
}
