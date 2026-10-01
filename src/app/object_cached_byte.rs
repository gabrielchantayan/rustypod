//! `FUN_082a270c` at load address 0x082a270c; true size 48 bytes.
//! Raw extent: 0x082a270c..0x082a273c, where the next push prologue starts.
//! Verified incoming calls: two plain BL (0x0817e198, 0x0817e1a8), zero
//! predicated BL; outgoing calls: one virtual BLX through vtable byte +8.
//! Call that predicate with the object; zero returns zero without touching
//! the cached pointer. Otherwise read the cached object's halfword at +0x54
//! and return its low byte. The caller uses it as a nonzero-gated value.
//! No deliberate behavioral deviations; raw u32 pointer words preserve
//! target object offsets on hosts, and repr(C) keeps the virtual slot at +8.

/// Only the verified prefix of the object's vtable.
#[repr(C)]
struct ObjectVtable {
    preceding_slots: [u32; 2],
    predicate: unsafe extern "C" fn(*mut u32) -> u32,
}

/// # Safety
/// `object` must have a valid vtable word and callable predicate at +8.
/// If the predicate returns nonzero, the updated object +8 word must point
/// to a readable, halfword-aligned cached object extending through +0x55.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_cached_byte(object: *mut u32) -> u32 {
    let vtable = object.read() as usize as *const ObjectVtable;
    if ((*vtable).predicate)(object) == 0 {
        return 0;
    }
    let cached = object.add(2).read() as usize as *const u8;
    (cached.add(0x54).cast::<u16>().read() & 0xff) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn predicate(object: *mut u32) -> u32 {
        object.add(1).read()
    }

    unsafe extern "C" fn redirect_cached(object: *mut u32) -> u32 {
        object.add(2).write(object.add(1).read());
        0x8000_0000
    }

    #[test]
    fn gates_invalid_cache_masks_high_byte_and_observes_predicate_updates() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OBJECT_CACHED_BYTE, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let object = slab.cast::<u32>();
            let vtable = slab.add(0x100).cast::<ObjectVtable>();
            let cached = slab.add(0x200);
            vtable.write(ObjectVtable { preceding_slots: [0; 2], predicate });
            object.write(vtable as usize as u32);
            object.add(1).write(0);
            object.add(2).write(0); // Must not be dereferenced on rejection.
            assert_eq!(object_cached_byte(object), 0);

            object.add(2).write(cached as usize as u32);
            for permitted in [1, 2, 0x8000_0000, u32::MAX] {
                object.add(1).write(permitted);
                for value in [0u16, 1, 0x00ff, 0xff00, 0x1234, 0xffff] {
                    cached.add(0x54).cast::<u16>().write(value);
                    assert_eq!(object_cached_byte(object), u32::from(value & 0xff));
                }
            }

            (*vtable).predicate = redirect_cached;
            object.add(1).write(cached as usize as u32);
            object.add(2).write(0); // Predicate supplies the valid cache.
            cached.add(0x54).cast::<u16>().write(0xabcd);
            assert_eq!(object_cached_byte(object), 0xcd);
        }
    }
}
