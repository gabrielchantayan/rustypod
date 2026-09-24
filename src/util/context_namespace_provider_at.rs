//! `context_namespace_provider_at` — original: `FUN_08070c10` @
//! `0x08070c10` (12 bytes; true extent `0x08070c10..0x08070c1c`; the next
//! independently linked wrapper begins at `0x08070c1c`).
//!
//! Raw A32 decoding verifies **2 inbound plain `bl` call sites**
//! (`0x0807777c` and `0x080ce4f8`) and **0 predicated `bl` call sites**. The
//! three words load `context->owner`, load that owner's namespace-provider
//! collection at target offset `+0x24`, then tail-branch to the already ported
//! [`crate::cxx::object_flags::namespace_provider_at`]. Ghidra's 72-byte
//! extent and three-call report conflate adjacent wrappers; raw firmware
//! establishes this boundary.
//!
//! Deliberate deviation: Rust makes the terminal branch a normal call. It
//! preserves the observed r0/r1 ABI and return value.

use core::ptr::addr_of;

/// Context whose owner supplies a namespace-provider collection.
#[repr(C)]
pub struct NamespaceProviderLookupContext {
    /// +0x00 on ARM: owner containing the provider collection.
    pub owner: *const NamespaceProviderLookupOwner,
}

/// Owner layout observed by the wrapper.
#[repr(C)]
pub struct NamespaceProviderLookupOwner {
    /// +0x00..+0x20: not read by this wrapper.
    pub unresolved_00: [u32; 9],
    /// +0x24 on ARM: namespace-provider collection.
    pub providers: *const u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 36] = [0; core::mem::offset_of!(NamespaceProviderLookupOwner, providers)];

/// Returns provider `index` from the collection owned by `context`.
///
/// `context` and its owner must be readable. Like retailOS, this wrapper does
/// not validate either pointer; a null provider collection is passed through
/// to [`crate::cxx::object_flags::namespace_provider_at`] and returns null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_namespace_provider_at(
    context: *const NamespaceProviderLookupContext,
    index: u32,
) -> *const u32 {
    let owner = unsafe { addr_of!((*context).owner).read_volatile() };
    let providers = unsafe { addr_of!((*owner).providers).read_volatile() };
    unsafe { crate::cxx::object_flags::namespace_provider_at(providers, index) }
}

#[cfg(test)]
mod tests {
    use super::{NamespaceProviderLookupContext, NamespaceProviderLookupOwner, context_namespace_provider_at};
    extern crate std;

    #[test]
    fn reads_owner_provider_table_at_requested_index() {
        let first = 0x1111_2222u32;
        let second = 0x3333_4444u32;
        let table = [&first as *const u32, &second as *const u32];
        let mut provider_bytes = [0u8; 4 + core::mem::size_of::<*const u32>()];
        unsafe {
            provider_bytes.as_mut_ptr().cast::<u32>().write_unaligned(2);
            provider_bytes.as_mut_ptr().add(4).cast::<*const *const u32>().write_unaligned(table.as_ptr());
        }
        let owner = NamespaceProviderLookupOwner {
            unresolved_00: [0; 9],
            providers: provider_bytes.as_ptr().cast(),
        };
        let context = NamespaceProviderLookupContext { owner: &owner };

        assert_eq!(unsafe { context_namespace_provider_at(&context, 1) }, &second);
    }

    #[test]
    fn forwards_null_provider_collection_to_accessor() {
        let owner = NamespaceProviderLookupOwner {
            unresolved_00: [0; 9],
            providers: core::ptr::null(),
        };
        let context = NamespaceProviderLookupContext { owner: &owner };

        assert!(unsafe { context_namespace_provider_at(&context, 0) }.is_null());
    }
}
