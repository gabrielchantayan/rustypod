//! Global object address getter — `FUN_081621e4` @ `0x081621e4` (8 bytes).
//!
//! Raw ARM extent is `0x081621e4..0x081621ec`: `ldr r0,[pc]` loads the
//! literal `0x08ad1778`, then `bx lr` returns it unchanged. The separately
//! linked next function begins at `0x081621f0`; the literal at `0x081621ec`
//! belongs to this getter. Decoding inbound direct ARM calls finds five plain,
//! unconditional `bl` calls and no predicated `bl` calls. The getter supplies
//! the static global object address to callers; neither the literal nor the
//! pointed-to object is dereferenced. Deliberate deviations: none.

/// Returns the address of the static global object used by its retailOS callers.
///
/// Original: `FUN_081621e4` @ `0x081621e4` (8 bytes, including its literal).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn global_object_address() -> u32 {
    0x08ad_1778
}

#[cfg(test)]
mod tests {
    use super::global_object_address;

    #[test]
    fn returns_static_object_address_without_dereferencing_it() {
        assert_eq!(global_object_address(), 0x08ad_1778);
    }
}
