//! Operator-cycle state transition used by the input parser.

use crate::kernel::sync_mutex::{mutex_lock, mutex_unlock, Mutex};

const LOCK_OFFSET: usize = 0xfc;
const OPERATOR_OFFSET: usize = 0x104;

/// `operator_cycle_advance_if_successor` — original: `FUN_081d1ae0` @
/// 0x081d1ae0 (132 bytes; 4 direct `bl` call sites: 3 plain, 1 predicated).
///
/// Optionally locks the state object's mutex at +0xfc, then replaces the
/// signed byte at +0x104 only when `candidate` is the next member of the
/// `*`, `+`, `,`, `-` cycle. Returns the resulting signed byte and optionally
/// unlocks. The two mutex calls are `blne` to the already ported
/// [`mutex_lock`] and [`mutex_unlock`]; no deliberate deviations.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn operator_cycle_advance_if_successor(
    state: *mut u8,
    candidate: i32,
    synchronize: i32,
) -> i32 {
    if synchronize != 0 {
        mutex_lock(state.add(LOCK_OFFSET).cast::<Mutex>());
    }

    let operator = state.add(OPERATOR_OFFSET).read() as i8 as i32;
    if (operator == b'*' as i32 && candidate == b'+' as i32)
        || (operator == b'+' as i32 && candidate == b',' as i32)
        || (operator == b',' as i32 && candidate == b'-' as i32)
        || (operator == b'-' as i32 && candidate == b'*' as i32)
    {
        state.add(OPERATOR_OFFSET).write(candidate as u8);
    }

    let result = state.add(OPERATOR_OFFSET).read() as i8 as i32;
    if synchronize != 0 {
        mutex_unlock(state.add(LOCK_OFFSET).cast::<Mutex>());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x200;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OPERATOR_CYCLE_ADVANCE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn state() -> Option<*mut u8> {
        // The target's mutex field is 4-byte aligned at +0xfc. Offset the
        // host fixture so its native pointer field is 8-byte aligned too.
        let state = unsafe { ((*FIXTURE)? as *mut u8).add(4) };
        unsafe { state.write_bytes(0, FIXTURE_LEN - 4) };
        Some(state)
    }

    #[test]
    fn advances_only_to_the_next_operator() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(state) = state() else {
            assert!(note_missing_u32_fixture("app/operator_cycle_advance_if_successor"));
            return;
        };

        for (current, candidate) in [(b'*', b'+'), (b'+', b','), (b',', b'-'), (b'-', b'*')] {
            unsafe { state.add(OPERATOR_OFFSET).write(current) };
            assert_eq!(unsafe { operator_cycle_advance_if_successor(state, candidate as i32, 0) }, candidate as i32);
            assert_eq!(unsafe { state.add(OPERATOR_OFFSET).read() }, candidate);
        }
    }

    #[test]
    fn preserves_non_successors_and_signed_return_values() {
        let _guard = FIXTURE_LOCK.lock();
        let Some(state) = state() else {
            assert!(note_missing_u32_fixture("app/operator_cycle_advance_if_successor"));
            return;
        };

        unsafe { state.add(OPERATOR_OFFSET).write(b'*') };
        assert_eq!(unsafe { operator_cycle_advance_if_successor(state, b'-' as i32, 1) }, b'*' as i32);
        assert_eq!(unsafe { state.add(OPERATOR_OFFSET).read() }, b'*');

        unsafe { state.add(OPERATOR_OFFSET).write(0x80) };
        assert_eq!(unsafe { operator_cycle_advance_if_successor(state, b'+' as i32, 0) }, -128);
        assert_eq!(unsafe { state.add(OPERATOR_OFFSET).read() }, 0x80);
    }
}
