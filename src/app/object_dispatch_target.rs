//! Opaque application-object dispatch-target accessor.
//!
//! `object_dispatch_target` — original: `FUN_0829919c` @ 0x0829919c
//! (8 bytes). Raw ARM is `ldr r0,[r0,#0x18]; bx lr`: return the untyped
//! word at object+0x18 with no NULL guard, no validation, and no writes.
//!
//! Call-site census (binary-scanned over every B/BL word in osos.dec):
//! 30 plain `bl` sites, zero predicated forms, plus one tail `b` from the
//! already-ported `singleton_state_get` wrapper @ 0x08086df0
//! (app/singleton_state.rs), which fetches the singleton base and
//! tail-branches here for the same +0x18 load. No data-word references to
//! 0x0829919c exist, so the accessor is never itself dispatched virtually.
//!
//! Every sampled caller treats the returned word as a vtable-bearing
//! object pointer: the settings dispatcher @ 0x0816f8ac and the command
//! cluster @ 0x08203a44 invoke its vtable slots +0x88/+0x8c with staged
//! three-word operation records, and the `singleton_state_get` callers do
//! the same through slot +0x84. The producing objects are heterogeneous
//! (registry class-0x6180 instances via `instance_of_class_6180` @
//! 0x08284e2c, dispatcher `this` pointers, the singleton base), so +0x18
//! is a shared dispatch-target member of this controller family; the
//! concrete target class is not recovered. The port therefore returns the
//! raw word and introduces no NULL check, exactly like the original.

/// object_dispatch_target — original: `FUN_0829919c` @ 0x0829919c
/// (8 bytes).
///
/// `ldr r0,[r0,#0x18]; bx lr` — returns the complete raw u32 word at
/// object+0x18. The original performs a single aligned word load; the port
/// matches it (no `read_unaligned` — +0x18 is word-aligned in every
/// recovered owner). No deviation: no NULL guard is added.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_dispatch_target(object: *const u8) -> u32 {
    unsafe { (object.add(0x18) as *const u32).read() }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn returns_the_exact_word_at_offset_0x18() {
        let mut object = [0u32; 8];
        object[6] = 0xdead_beef;

        unsafe {
            assert_eq!(object_dispatch_target(object.as_ptr() as *const u8), 0xdead_beef);
        }
    }

    #[test]
    fn returns_extreme_values_unmodified() {
        let mut object = [0u32; 8];

        for value in [0u32, 0xffff_ffff, 0x0800_0000, 1] {
            object[6] = value;
            unsafe {
                assert_eq!(object_dispatch_target(object.as_ptr() as *const u8), value);
            }
        }
    }

    #[test]
    fn reads_only_the_word_at_offset_0x18() {
        let mut object = [0xaaaa_aaaau32; 8];
        object[6] = 0x1234_5678;
        let before = object;

        unsafe {
            assert_eq!(object_dispatch_target(object.as_ptr() as *const u8), 0x1234_5678);
        }
        assert_eq!(object, before, "accessor must not write the object");
    }

    #[test]
    fn distinct_objects_yield_their_own_word() {
        let mut first = [0u32; 8];
        let mut second = [0u32; 8];
        first[6] = 0x1111_1111;
        second[6] = 0x2222_2222;

        unsafe {
            assert_eq!(object_dispatch_target(first.as_ptr() as *const u8), 0x1111_1111);
            assert_eq!(object_dispatch_target(second.as_ptr() as *const u8), 0x2222_2222);
            // No caching: re-reading the first object still sees its word.
            first[6] = 0x3333_3333;
            assert_eq!(object_dispatch_target(first.as_ptr() as *const u8), 0x3333_3333);
        }
    }
}
