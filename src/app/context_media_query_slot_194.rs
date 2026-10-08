//! Query slot +0x194 of an application context's media interface.
//!
//! Original `FUN_081114dc` at `0x081114dc`, true size **16 bytes**, ending
//! at the separate signed-property helper `0x081114ec`. Raw A32 words:
//! e5900888 e5901000 e5911194 e12fff11. Whole-image aligned decoding verifies
//! two inbound plain BLs (0x08114774, 0x08232bf0), zero predicated inbound
//! BLs, zero outbound plain/predicated BLs and one BX virtual tail dispatch.
//! Load context +0x888, load its interface's vtable slot +0x194, and invoke
//! with that interface as receiver. Preserve the full returned word; both
//! callers test zero/nonzero. The concrete method's identity is unproven.
//!
//! Deliberate deviations: repr(C) host pointers widen while preserving field
//! and vtable word indices. Rust expresses the tail dispatch as a final call;
//! there are no null guards, fixed-address seams or result normalization.
//! Codegen review: LLVM retains all three exact loads and the final BX,
//! adding only a frame-pointer push/setup/pop around the tail dispatch.

#[repr(C)]
pub struct MediaQuery194Vtable {
    pub reserved: [usize; 0x194 / 4],
    pub query: unsafe extern "C" fn(*mut MediaQuery194Interface) -> u32,
}

#[repr(C)]
pub struct MediaQuery194Interface {
    pub vtable: *const MediaQuery194Vtable,
}

#[repr(C)]
pub struct MediaQuery194Context {
    pub reserved: [u32; 0x888 / 4],
    pub interface: *mut MediaQuery194Interface,
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x888] = [(); core::mem::offset_of!(MediaQuery194Context, interface)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0x194] = [(); core::mem::offset_of!(MediaQuery194Vtable, query)];

/// Invoke the media interface query without changing its returned word.
///
/// # Safety
/// The context, interface and vtable must be readable and aligned, and the
/// query slot must be callable with the interface, including any mutable
/// storage the concrete method accesses. Retail performs no null checks.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_media_query_slot_194(context: *mut MediaQuery194Context) -> u32 {
    let interface = (*context).interface;
    ((*(*interface).vtable).query)(interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct QueryState {
        interface: MediaQuery194Interface,
        value: u32,
    }

    unsafe extern "C" fn advance(interface: *mut MediaQuery194Interface) -> u32 {
        let state = &mut *interface.cast::<QueryState>();
        let value = state.value;
        state.value = value.wrapping_add(1);
        value
    }

    #[test]
    fn query_preserves_unsigned_results_mutation_and_replaced_receiver() {
        let table = MediaQuery194Vtable { reserved: [0; 0x194 / 4], query: advance };
        let mut first = QueryState {
            interface: MediaQuery194Interface { vtable: &table }, value: u32::MAX,
        };
        let mut second = QueryState {
            interface: MediaQuery194Interface { vtable: &table }, value: 0x8000_0000,
        };
        let mut context = MediaQuery194Context {
            reserved: [0x12345678; 0x888 / 4], interface: &mut first.interface,
        };
        for expected in [u32::MAX, 0, 1] {
            assert_eq!(unsafe { context_media_query_slot_194(&mut context) }, expected);
            assert_eq!(first.value, expected.wrapping_add(1));
        }
        context.interface = &mut second.interface;
        assert_eq!(unsafe { context_media_query_slot_194(&mut context) }, 0x8000_0000);
        assert_eq!(second.value, 0x8000_0001);
        assert_eq!(first.value, 2);
        assert_eq!(context.reserved, [0x12345678; 0x888 / 4]);
    }
}
