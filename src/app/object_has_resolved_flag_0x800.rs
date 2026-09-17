//! RetailOS port of `FUN_082a331c` at load address `0x082a331c` (84 bytes).
//!
//! Raw ARM establishes the true extent `0x082a331c..0x082a3370`; the next
//! `push {r4, lr}` at `0x082a3370` begins a distinct function. There are four
//! incoming plain `bl` calls and no predicated forms. The function first calls
//! vtable slot `+8`; when it permits the query, it uses the object's cached
//! resolved-object word at `+8`, or resolves the `+4` successor link through
//! `0x082a2cac`, then returns bit 11 from the resolved object's `+0x1c` flags.
//!
//! Deliberate deviation: the two unported call targets are target-address
//! calls on ARM and host-test seams elsewhere, preserving their verified ABIs
//! without assigning either an unsupported semantic identity.

/// ABI of the object-specific predicate at vtable byte offset `+8`.
type ObjectPredicate = unsafe extern "C" fn(*mut u32) -> u32;
/// ABI of retailOS `FUN_082a2cac` at `0x082a2cac`.
type SuccessorResolve = unsafe extern "C" fn(*mut u32, *mut u32) -> *mut u32;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn object_predicate(object: *mut u32) -> u32 {
    let vtable = object.read() as *const u32;
    let predicate: ObjectPredicate = core::mem::transmute(vtable.add(2).read() as usize);
    predicate(object)
}

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn resolve_successor(object: *mut u32, successor: *mut u32) -> *mut u32 {
    let resolve: SuccessorResolve = core::mem::transmute(0x082a_2cacusize);
    resolve(object, successor)
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_object_predicate(_object: *mut u32) -> u32 {
    0
}

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn missing_successor_resolve(_object: *mut u32, _successor: *mut u32) -> *mut u32 {
    core::ptr::null_mut()
}

#[cfg(not(target_arch = "arm"))]
static mut OBJECT_PREDICATE: ObjectPredicate = missing_object_predicate;
#[cfg(not(target_arch = "arm"))]
static mut SUCCESSOR_RESOLVE: SuccessorResolve = missing_successor_resolve;

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn object_predicate(object: *mut u32) -> u32 {
    OBJECT_PREDICATE(object)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn resolve_successor(object: *mut u32, successor: *mut u32) -> *mut u32 {
    SUCCESSOR_RESOLVE(object, successor)
}

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_has_resolved_flag_0x800(object: *mut u32) -> u32 {
    if object_predicate(object) == 0 {
        return 0;
    }

    let mut resolved = object.add(2).read() as *mut u32;
    if resolved.is_null() {
        resolved = resolve_successor(object, object.add(1).read() as *mut u32);
        if resolved.is_null() {
            return 0;
        }
    }

    (resolved.add(7).read() & 0x800) >> 11
}
#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;
    use parking_lot::Mutex;
    use super::*;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut PREDICATE_RESULT: u32 = 0;
    static mut RESOLVED: *mut u32 = ptr::null_mut();
    static mut PREDICATE_CALLS: u32 = 0;
    static mut RESOLVE_CALLS: u32 = 0;
    static mut SEEN_OBJECT: *mut u32 = ptr::null_mut();
    static mut SEEN_SUCCESSOR: *mut u32 = ptr::null_mut();

    unsafe extern "C" fn predicate(object: *mut u32) -> u32 {
        PREDICATE_CALLS += 1;
        SEEN_OBJECT = object;
        PREDICATE_RESULT
    }

    unsafe extern "C" fn resolve(object: *mut u32, successor: *mut u32) -> *mut u32 {
        RESOLVE_CALLS += 1;
        SEEN_OBJECT = object;
        SEEN_SUCCESSOR = successor;
        RESOLVED
    }

    #[test]
    fn gates_resolution_and_extracts_only_flag_bit_11() {
        let _guard = SEAM_LOCK.lock();
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OBJECT_HAS_RESOLVED_FLAG_0X800,
            0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        let object = slab.cast::<u32>();
        let successor = unsafe { slab.add(0x100).cast::<u32>() };
        let cached = unsafe { slab.add(0x200).cast::<u32>() };

        unsafe {
            OBJECT_PREDICATE = predicate;
            SUCCESSOR_RESOLVE = resolve;
            object.write(0);
            object.add(1).write(successor as usize as u32);
            object.add(2).write(cached as usize as u32);
            cached.add(7).write(0x1800);

            PREDICATE_RESULT = 0;
            PREDICATE_CALLS = 0;
            RESOLVE_CALLS = 0;
            assert_eq!(object_has_resolved_flag_0x800(object), 0);
            assert_eq!(PREDICATE_CALLS, 1);
            assert_eq!(RESOLVE_CALLS, 0);

            PREDICATE_RESULT = 1;
            PREDICATE_CALLS = 0;
            assert_eq!(object_has_resolved_flag_0x800(object), 1);
            assert_eq!(PREDICATE_CALLS, 1);
            assert_eq!(RESOLVE_CALLS, 0);

            object.add(2).write(0);
            RESOLVED = successor;
            successor.add(7).write(0x400);
            RESOLVE_CALLS = 0;
            assert_eq!(object_has_resolved_flag_0x800(object), 0);
            assert_eq!(RESOLVE_CALLS, 1);
            assert_eq!(SEEN_OBJECT, object);
            assert_eq!(SEEN_SUCCESSOR, successor);

            RESOLVED = ptr::null_mut();
            assert_eq!(object_has_resolved_flag_0x800(object), 0);
        }
    }
}
