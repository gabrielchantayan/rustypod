//! Target-size predicate from `FUN_081164fc` @ `0x081164fc`, 120 bytes.
//!
//! Raw A32 spans [0x081164fc, 0x08116574), the next real function boundary.
//! Verified calls: two inbound unconditional BLs (0x081f879c, 0x081f87d0),
//! zero predicated BLs; one outgoing BL to record_layout_size and four BLX.
//! If target slot +0x8c is nonzero and its first slot +0x88 result differs
//! from the record-layout size, return whether a fresh +0x88 result is at
//! most the +0x5c result (unsigned). Reload the owner's target before every
//! virtual call. Callers select text for events 0x7f22 and 0x7f23; the target
//! methods' concrete identities remain unrecovered.
//!
//! Deliberate deviation: host fixtures use native pointers at the same owner
//! byte offset and native-width vtable slots, rather than truncated pointers.

use super::object_state::record_layout_size;

type TargetQuery = unsafe extern "C" fn(*mut u8) -> u32;
const TARGET_OFFSET: usize = 0x88c;

#[inline(always)]
unsafe fn query(owner: *mut u8, slot: usize) -> u32 {
    #[cfg(target_os = "none")]
    let target = owner.add(TARGET_OFFSET).cast::<u32>().read_volatile() as usize as *mut u8;
    #[cfg(not(target_os = "none"))]
    let target = owner.add(TARGET_OFFSET).cast::<*mut u8>().read_unaligned();
    let vtable = target.cast::<*const TargetQuery>().read();
    let method = vtable.add(slot / 4).read();
    method(target)
}

#[inline(always)]
unsafe fn within_limit(owner: *mut u8, layout_size: impl FnOnce() -> u32) -> u32 {
    if query(owner, 0x8c) == 0 { return 0; }
    let initial_size = query(owner, 0x88);
    if initial_size == layout_size() { return 0; }
    let limit = query(owner, 0x5c);
    u32::from(query(owner, 0x88) <= limit)
}

/// # Safety
/// `owner` must contain a valid target pointer at +0x88c. Each reloaded target
/// must have a valid vtable with query methods at +0x5c, +0x88 and +0x8c.
/// No NULL guard is present in retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn target_size_within_limit(owner: *mut u8) -> u32 {
    within_limit(owner, || record_layout_size())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Target {
        vtable: *const TargetQuery,
        enabled: u32,
        initial: u32,
        final_size: u32,
        limit: u32,
        size_calls: u32,
        limit_calls: u32,
        owner: *mut u8,
        replacement: *mut u8,
    }
    unsafe extern "C" fn enabled(target: *mut u8) -> u32 { (*target.cast::<Target>()).enabled }
    unsafe extern "C" fn size(target: *mut u8) -> u32 {
        let target = &mut *target.cast::<Target>();
        target.size_calls += 1;
        if target.size_calls == 1 { target.initial } else { target.final_size }
    }
    unsafe extern "C" fn limit(target: *mut u8) -> u32 {
        let target = &mut *target.cast::<Target>();
        target.limit_calls += 1;
        if !target.replacement.is_null() {
            target.owner.add(TARGET_OFFSET).cast::<*mut u8>().write_unaligned(target.replacement);
        }
        target.limit
    }

    #[test]
    fn short_circuits_and_compares_fresh_unsigned_size() {
        let mut slots = [enabled as TargetQuery; 36];
        slots[0x88 / 4] = size;
        slots[0x5c / 4] = limit;
        let mut owner = [0u8; TARGET_OFFSET + core::mem::size_of::<*mut u8>()];
        let mut target = Target { vtable: slots.as_ptr(), enabled: 0, initial: 7,
            final_size: 9, limit: 9, size_calls: 0, limit_calls: 0,
            owner: owner.as_mut_ptr(), replacement: core::ptr::null_mut() };
        unsafe {
            owner.as_mut_ptr().add(TARGET_OFFSET).cast::<*mut Target>().write_unaligned(&mut target);
            assert_eq!(target_size_within_limit(owner.as_mut_ptr()), 0);
            assert_eq!(target.size_calls, 0);
            target.enabled = 1;
            assert_eq!(within_limit(owner.as_mut_ptr(), || 7), 0);
            assert_eq!((target.size_calls, target.limit_calls), (1, 0));
            for (final_size, bound, expected) in [(0, 0, 1), (9, 9, 1), (10, 9, 0),
                (0x8000_0000, 0x7fff_ffff, 0), (u32::MAX, u32::MAX, 1)] {
                target.size_calls = 0; target.final_size = final_size; target.limit = bound;
                assert_eq!(within_limit(owner.as_mut_ptr(), || 0x100), expected);
                assert_eq!(target.size_calls, 2);
            }
        }
    }

    #[test]
    fn reloads_target_after_limit_query() {
        let mut slots = [enabled as TargetQuery; 36];
        slots[0x88 / 4] = size; slots[0x5c / 4] = limit;
        let mut owner = [0u8; TARGET_OFFSET + core::mem::size_of::<*mut u8>()];
        let mut replacement = Target { vtable: slots.as_ptr(), enabled: 1, initial: 11,
            final_size: 0, limit: 0, size_calls: 0, limit_calls: 0,
            owner: owner.as_mut_ptr(), replacement: core::ptr::null_mut() };
        let mut target = Target { vtable: slots.as_ptr(), enabled: 1, initial: 7,
            final_size: 0, limit: 10, size_calls: 0, limit_calls: 0,
            owner: owner.as_mut_ptr(), replacement: (&mut replacement as *mut Target).cast() };
        unsafe {
            owner.as_mut_ptr().add(TARGET_OFFSET).cast::<*mut Target>().write_unaligned(&mut target);
            assert_eq!(within_limit(owner.as_mut_ptr(), || 0x100), 0);
        }
        assert_eq!(target.size_calls, 1);
        assert_eq!(replacement.size_calls, 1);
    }
}
