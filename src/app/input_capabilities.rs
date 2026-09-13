//! Lazy getter for the input-capabilities interface singleton.
//!
//! `FUN_08258bd0` @ **0x08258bd0** has 48 instruction bytes plus its two
//! literal-pool words, a **56-byte** true extent ending before the separately
//! linked function at 0x08258c08. A full raw decode of every ARM `B`/`BL`
//! word in `osos.dec` finds **7 direct, unconditional `bl` call sites** and
//! no predicated calls or direct tail branches.
//!
//! The getter reads its cache word at 0x089d0298. On a miss it allocates four
//! bytes with `operator_new`, plants the vtable word 0x089a778c, caches the
//! allocation, and reloads that cache before returning. The observed callers
//! use virtual slots +0x14 through +0x2c as input-capability probes, so the
//! interface is named only for that proven role. Several vtable words land
//! inside the 0x08105b58 instruction/jump-table stream rather than verified
//! function entries; this port stores the literal without inventing callee
//! identities.
//!
//! Deliberate deviation: the firmware cache word is represented by a crate
//! static. The original stores through the allocation without a NULL check;
//! this unsafe entry retains that precondition.

use crate::heap::veneers::operator_new;

/// The one-word object's literal vtable address (`DAT_08258c04`).
pub const INPUT_CAPABILITIES_VTABLE_ADDRESS: u32 = 0x089a_778c;

/// The firmware cache word at 0x089d0298.
pub static mut INPUT_CAPABILITIES_INSTANCE: *mut u8 = core::ptr::null_mut();

/// input_capabilities_get — original: `FUN_08258bd0` @ **0x08258bd0**
/// (48 code bytes + 8 literal-pool bytes = **56 bytes** true extent; **7
/// direct unconditional `bl` call sites**, zero predicated calls and zero
/// direct plain-`b` tails, verified from the raw image).
///
/// Returns the one-word input-capability interface, allocating and planting
/// its 0x089a778c vtable on the first call. Like the ARM `str r1, [r0]`, a
/// failed allocation is not guarded before the vtable write.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn input_capabilities_get() -> *mut u8 {
    let cache = core::ptr::addr_of_mut!(INPUT_CAPABILITIES_INSTANCE);
    if core::ptr::read_volatile(cache).is_null() {
        let instance = operator_new(core::mem::size_of::<u32>());
        core::ptr::write_volatile(instance.cast::<u32>(), INPUT_CAPABILITIES_VTABLE_ADDRESS);
        core::ptr::write_volatile(cache, instance);
    }
    core::ptr::read_volatile(cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(align(4))]
    struct AlignedArena([u8; core::mem::size_of::<u32>()]);

    static mut ARENA: AlignedArena = AlignedArena([0; core::mem::size_of::<u32>()]);

    #[test]
    fn allocates_one_word_plants_vtable_and_caches_instance() {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            let arena = ptr::addr_of_mut!(ARENA).cast::<u8>();
            ARENA.0 = [0; core::mem::size_of::<u32>()];
            INPUT_CAPABILITIES_INSTANCE = ptr::null_mut();
            crate::heap::veneers::tests::set_alloc_ret(arena);

            assert_eq!(input_capabilities_get(), arena);
            assert_eq!(crate::heap::veneers::tests::alloc_log(), (1, 4, 2));
            assert_eq!(ptr::read_volatile(arena.cast::<u32>()), INPUT_CAPABILITIES_VTABLE_ADDRESS);

            assert_eq!(input_capabilities_get(), arena);
            assert_eq!(crate::heap::veneers::tests::alloc_log().0, 1, "cached call must not allocate");
            INPUT_CAPABILITIES_INSTANCE = ptr::null_mut();
        }
        drop(guard);
    }
}
