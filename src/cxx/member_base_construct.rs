//! Member-base constructor @ 0x0827c094 (FUN_0827c094).
//! True extent: 24 bytes (20 code + 4-byte literal), next entry 0x0827c0ac.
//! Raw-word verification: zero outgoing plain/predicated BLs; two incoming
//! plain BLs at 0x0827c358 and 0x0827c4ec, zero predicated incoming BLs.
//! Install vtable 0x089a8268, clear the second target word, and return this.
//! Raw r0 is unchanged; Ghidra's void return loses the callers' live result.
//! Deliberate deviations: none. Fields use aligned target-width word accesses.

/// # Safety
/// `this` must point to at least two aligned, writable u32 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn member_base_construct(this: *mut u32) -> *mut u32 {
    unsafe {
        this.write_volatile(0x089a_8268);
        this.add(1).write_volatile(0);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_both_words_preserves_neighbors_and_returns_this() {
        for initial in [0, 1, 0x8000_0000, u32::MAX] {
            let mut words = [0x1357_9bdf, initial, !initial, 0x2468_ace0];
            let this = unsafe { words.as_mut_ptr().add(1) };
            assert_eq!(unsafe { member_base_construct(this) }, this);
            assert_eq!(words, [0x1357_9bdf, 0x089a_8268, 0, 0x2468_ace0]);
            assert_eq!(unsafe { member_base_construct(this) }, this);
            assert_eq!(words, [0x1357_9bdf, 0x089a_8268, 0, 0x2468_ace0]);
        }
    }
}
