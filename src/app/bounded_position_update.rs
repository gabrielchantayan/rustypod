//! Bounded absolute/relative position update.
//!
//! Original `FUN_081fcc64` at 0x081fcc64, 220 bytes through 0x081fcd40
//! (next function's push). Raw A32 decoding: two incoming plain BLs at
//! 0x082085cc and 0x0822c148, no predicated incoming BLs, no outgoing BLs.
//! Position is the signed word at +0x2b4; bound is the signed word at +0x2b8.
//! Relative mode rejects an invalid old position, adds with wrapping, then
//! clamps negative results to zero and results >= a nonzero bound to bound-1.
//! Absolute mode rejects negative requests; a nonzero bound clamps to bound-1
//! and reports the wrapping difference only for a nonnegative old position.
//! A zero bound accepts the absolute request but reports zero difference.
//! Rejections leave state and output untouched. Successful relative updates
//! always report zero. Deliberate deviation: structured branches replace
//! predicated instructions; word-indexed state preserves target offsets on hosts.

/// # Safety
/// `state` must point to at least 175 aligned, readable/writable i32 words.
/// `difference` must be writable on success; it may alias a state word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn bounded_position_update(
    state: *mut i32, absolute: u32, request: i32, difference: *mut i32,
) -> u32 {
    let position = state.add(0x2b4 / 4);
    let bound = state.add(0x2b8 / 4);
    let mut delta = 0;
    if absolute != 0 {
        if request < 0 {
            return 0;
        }
        let limit = bound.read();
        if limit == 0 {
            position.write(request);
        } else {
            let old = position.read();
            let next = if request < limit { request } else { limit.wrapping_sub(1) };
            if old >= 0 {
                delta = next.wrapping_sub(old);
            }
            position.write(next);
        }
    } else {
        let old = position.read();
        if old < 0 {
            return 0;
        }
        let next = old.wrapping_add(request);
        position.write(next);
        if next < 0 {
            position.write(0);
        } else {
            let limit = bound.read();
            if limit != 0 && next >= limit {
                position.write(limit.wrapping_sub(1));
            }
        }
    }
    difference.write(delta);
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(old: i32, limit: i32, absolute: u32, request: i32) -> Option<(i32, i32)> {
        if absolute == 0 {
            if old < 0 { return None; }
            let sum = ((old as u32 as u64 + request as u32 as u64) & 0xffff_ffff) as u32 as i32;
            let next = if sum < 0 { 0 } else if limit != 0 && sum >= limit {
                (limit as u32).wrapping_sub(1) as i32
            } else { sum };
            Some((next, 0))
        } else {
            if request < 0 { return None; }
            let next = if limit != 0 && request >= limit {
                (limit as u32).wrapping_sub(1) as i32
            } else { request };
            let delta = if limit != 0 && old >= 0 {
                (next as i64 - old as i64) as i32
            } else { 0 };
            Some((next, delta))
        }
    }

    #[test]
    fn signed_bounds_modes_and_wrapping_match_reference() {
        let values = [i32::MIN, -2, -1, 0, 1, 2, 7, i32::MAX - 1, i32::MAX];
        for old in values {
            for limit in values {
                for request in values {
                    for mode in [0, 1, 7, u32::MAX] {
                        let mut state = [0x12345678; 176];
                        state[173] = old;
                        state[174] = limit;
                        let before = state;
                        let mut delta = 0x76543210;
                        let expected = reference(old, limit, mode, request);
                        let result = unsafe { bounded_position_update(state.as_mut_ptr(), mode, request, &mut delta) };
                        assert_eq!(result, expected.is_some() as u32);
                        let mut expected_state = before;
                        if let Some((next, expected_delta)) = expected {
                            expected_state[173] = next;
                            assert_eq!(delta, expected_delta);
                        } else {
                            assert_eq!(delta, 0x76543210);
                        }
                        assert_eq!(state, expected_state);
                    }
                }
            }
        }
    }

    #[test]
    fn success_output_aliases_position_after_update() {
        let mut state = [0; 175];
        state[173] = 3;
        state[174] = 10;
        let pointer = state.as_mut_ptr();
        assert_eq!(unsafe { bounded_position_update(pointer, 1, 8, pointer.add(173)) }, 1);
        assert_eq!(state[173], 5);
        assert_eq!(state[174], 10);
    }

    #[test]
    fn rejection_never_accesses_output() {
        let mut state = [0; 175];
        state[173] = -1;
        assert_eq!(unsafe { bounded_position_update(state.as_mut_ptr(), 0, 3, core::ptr::null_mut()) }, 0);
        assert_eq!(unsafe { bounded_position_update(state.as_mut_ptr(), 1, -1, core::ptr::null_mut()) }, 0);
        assert_eq!(state[173], -1);
    }
}
