//! `named_object_prefix_construct` — retailOS `FUN_08207674` @ `0x08207674`.
//!
//! True extent: 20 bytes, `0x08207674..0x08207688`: four ARM instructions
//! and the vtable literal at `0x08207684`. The next function is a separately
//! referenced `bx lr` at `0x08207688`, not padding or part of this constructor.
//! Whole-image ARM decoding finds two plain inbound BLs (`0x081e7404` and
//! `0x081eff10`), zero predicated inbound BLs, and zero outbound BLs.
//!
//! Store the full-width name word at +4, install vtable `0x089919a8` at +0,
//! and return this unchanged in r0. Both derived constructors replace the
//! vtable and initialize further words. Concrete class identity is unresolved.
//! Deliberate deviations: volatile stores preserve the original write order;
//! Rust explicitly returns the pointer omitted by Ghidra's void signature.
//! No name dereference, validation, or additional field initialization.

pub const NAMED_OBJECT_PREFIX_VTABLE_ADDRESS: u32 = 0x0899_19a8;

/// Initialize the two-word named-object base prefix.
///
/// # Safety
/// `this` must point to at least eight writable bytes aligned for `u32`.
/// `name` is a target address word; it is stored without dereferencing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.named_object_prefix_construct")]
#[inline(never)]
pub unsafe extern "C" fn named_object_prefix_construct(this: *mut u8, name: u32) -> *mut u8 {
    unsafe {
        this.cast::<u32>().add(1).write_volatile(name);
        this.cast::<u32>().write_volatile(NAMED_OBJECT_PREFIX_VTABLE_ADDRESS);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_full_name_word_neighbors_and_derived_fields() {
        for pattern in [0_u32, 0xa5a5_a5a5, u32::MAX] {
            for name in [0, 1, 0x0800_0000, 0x8000_0000, u32::MAX] {
                let mut words = [pattern; 6];
                let this = unsafe { words.as_mut_ptr().add(1).cast::<u8>() };
                let returned = unsafe { named_object_prefix_construct(this, name) };
                assert_eq!(returned, this);
                assert_eq!(words, [pattern, NAMED_OBJECT_PREFIX_VTABLE_ADDRESS,
                    name, pattern, pattern, pattern]);
            }
        }
    }
}
