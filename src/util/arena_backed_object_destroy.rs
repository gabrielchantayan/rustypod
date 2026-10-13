//! Arena-backed object teardown — `FUN_08038ef8` @ `0x08038ef8`.
//!
//! Raw extent: 76 bytes, `0x08038ef8..0x08038f44`; the next function starts
//! with `cmp r0,#0`. Two inbound plain BLs (0x080392c8, 0x08138394), no
//! predicated inbound BLs. Outbound: three plain BLs, two BLNEs, and a final
//! tail B to the empty destructor at 0x08057164.
//!
//! Reads object words +0xb0, +0x10c, and +0x144; a nonzero +0x10c points
//! to a record whose +8 word is also read. All four destructor calls and
//! the final tail call are verified `bx lr` no-ops. The leaf at 0x08057168
//! resets arena word 1 from word 0, then word 2 from word 3. Returns the
//! original object, leaving its fields and backing storage untouched.
//!
//! Deliberate deviations: omit the verified inert calls, retain their field
//! reads with volatile aligned words, and inline the fully decoded arena
//! reset instead of creating a fixed-address call seam. Host arena backing
//! uses the allocator's existing state override.
//!
//! Host tests and ARM build pass; match.py shows 19 stock versus 15 Rust entries: inert calls removed, arena reset inlined, original r0 preserved.

/// # Safety
/// `object` must be word-aligned and readable through +0x144. A nonzero
/// word at +0x10c must address an aligned record readable through +8.
/// The shared arena state must contain four writable words; callers must
/// serialize its mutation with allocation and other arena users.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn arena_backed_object_destroy(object: *mut u32) -> *mut u32 {
    let _ = object.add(0xb0 / 4).read_volatile();
    let nested = object.add(0x10c / 4).read_volatile();
    if nested != 0 {
        let _ = (nested as usize as *const u32).add(2).read_volatile();
        let _ = object.add(0x10c / 4).read_volatile();
    }
    let _ = object.add(0x144 / 4).read_volatile();
    let arena = super::zeroing_bump_alloc::arena_state();
    arena.add(1).write_volatile(arena.read_volatile());
    arena.add(2).write_volatile(arena.add(3).read_volatile());
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::zeroing_bump_alloc::{ZEROING_BUMP_ARENA_STATE, tests::TEST_LOCK};
    use crate::testing::{hints, try_map_u32_slab};

    struct Restore(*mut u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ZEROING_BUMP_ARENA_STATE = self.0; }
        }
    }

    #[test]
    fn resets_arena_without_destroying_optional_records_or_object() {
        let _lock = TEST_LOCK.lock();
        let slab = try_map_u32_slab(hints::ARENA_BACKED_OBJECT_DESTROY, 0x1000)
            .expect("target-width teardown fixture");
        unsafe {
            let nested = slab.cast::<u32>();
            nested.write(0x1234_5678);
            nested.add(1).write(0x8765_4321);
            let mut arena = [0u32; 4];
            let _restore = Restore(ZEROING_BUMP_ARENA_STATE);
            ZEROING_BUMP_ARENA_STATE = arena.as_mut_ptr();
            for base in [0, 0x0800_0000, u32::MAX] {
                for capacity in [0, 1, u32::MAX] {
                    for link in [0, nested as usize as u32] {
                        for payload in [0, u32::MAX] {
                            nested.add(2).write(payload);
                            let mut object = [0xa5a5_a5a5u32; 0x16c / 4];
                            object[0xb0 / 4] = payload;
                            object[0x10c / 4] = link;
                            object[0x144 / 4] = payload;
                            let before = object;
                            arena = [base, 0x1111_1111, 0x2222_2222, capacity];
                            let pointer = object.as_mut_ptr();
                            assert_eq!(arena_backed_object_destroy(pointer), pointer);
                            assert_eq!(arena, [base, base, capacity, capacity]);
                            assert_eq!(object, before);
                            assert_eq!(core::slice::from_raw_parts(nested, 3),
                                &[0x1234_5678, 0x8765_4321, payload]);
                        }
                    }
                }
            }
        }
    }
}
