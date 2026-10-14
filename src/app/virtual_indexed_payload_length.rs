//! Encoded payload length selected by an embedded virtual entry provider.

use super::indexed_payload_lookup::indexed_payload_lookup_mode_one;

#[repr(C)]
pub struct EntryProviderVtable {
    pub preceding_slots: [usize; 6],
    pub entry_word: unsafe extern "C" fn(*mut EntryProvider) -> *const u32,
}

#[repr(C)]
pub struct EntryProvider {
    pub vtable: *const EntryProviderVtable,
}

/// Retail prefix: index at +0x14 and embedded provider at +0x1c on ARM.
#[repr(C)]
pub struct VirtualIndexedPayload {
    pub prefix: [u32; 5],
    pub index: *mut u8,
    pub reserved: u32,
    pub provider: EntryProvider,
}

/// virtual_indexed_payload_length — FUN_083d6490 @ 0x083d6490.
/// True extent: 52 bytes, [0x083d6490, 0x083d64c4); the next function
/// starts with ldr r0,[r0]. Raw code has one plain outbound BL, zero
/// predicated BLs, and one BLX through virtual slot +0x18. No inbound BL
/// occurs in Ghidra's instruction listing; a whole-image word scan has one
/// conditional candidate at 0x088a9e78, absent from that listing and not
/// established as executable code.
/// Invoke the embedded provider, dereference its returned entry word, then
/// perform a mode-one indexed lookup and return encoded length, ignoring
/// status and payload. Incoming r2/r3 seed output scratch that the backend
/// always overwrites, so these are not semantic arguments.
/// Deliberate deviations: native pointer fields and vtable slots widen on
/// hosts via repr(C); target offsets remain unchanged. Scratch is initialized
/// rather than seeded from unused incoming registers. No callee identity is
/// claimed for the dynamic virtual slot.
///
/// # Safety
/// Object and provider vtable must be valid; the slot must accept the embedded
/// provider and return a readable aligned entry word. The index must satisfy
/// indexed_payload_lookup_mode_one's contract after the virtual call.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn virtual_indexed_payload_length(object: *mut VirtualIndexedPayload) -> u32 {
    let provider = core::ptr::addr_of_mut!((*object).provider);
    let entry = ((*(*provider).vtable).entry_word)(provider).read();
    let mut payload = core::ptr::null_mut();
    let mut length = 0;
    indexed_payload_lookup_mode_one((*object).index, entry, &mut payload, &mut length);
    length
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use crate::util::{crts_tag::CRTS_TAG, string_pool::PoolEntry};

    #[repr(C)]
    struct Fixture {
        object: VirtualIndexedPayload,
        entry: u32,
        replacement_index: *mut u8,
    }

    unsafe extern "C" fn select_entry(provider: *mut EntryProvider) -> *const u32 {
        let offset = core::mem::offset_of!(VirtualIndexedPayload, provider);
        let fixture = provider.cast::<u8>().sub(offset).cast::<Fixture>();
        // The original loads index only after invoking the virtual provider.
        (*fixture).object.index = (*fixture).replacement_index;
        core::ptr::addr_of!((*fixture).entry)
    }

    #[test]
    fn virtual_selection_returns_length_not_status_and_observes_index_mutation() {
        unsafe {
            let Some(slab) = try_map_u32_slab(hints::VIRTUAL_INDEXED_PAYLOAD_LENGTH, 4096) else { return; };
            core::ptr::write_bytes(slab, 0, 4096);
            let index = slab.cast::<u32>();
            let handle = slab.add(128).cast::<u32>();
            let blob_handle = slab.add(132).cast::<u32>();
            let entry = slab.add(160).cast::<PoolEntry>();
            index.write(CRTS_TAG);
            index.add(2).write(handle as usize as u32);
            index.add(4).write(blob_handle as usize as u32);
            index.add(7).write(1);
            handle.write(entry as usize as u32);
            blob_handle.write(slab.add(256) as usize as u32);
            entry.write(PoolEntry { blob_offset: 0, length: 37 });
            let vtable = EntryProviderVtable { preceding_slots: [0; 6], entry_word: select_entry };
            let mut fixture = Fixture {
                object: VirtualIndexedPayload {
                    prefix: [0; 5], index: core::ptr::null_mut(), reserved: 0,
                    provider: EntryProvider { vtable: &vtable },
                },
                entry: 1, replacement_index: slab,
            };
            assert_eq!(virtual_indexed_payload_length(&mut fixture.object), 37);
            for selected in [0, 2, u32::MAX] {
                fixture.entry = selected;
                assert_eq!(virtual_indexed_payload_length(&mut fixture.object), 0);
            }
            fixture.entry = 1;
            for length in [0, -1, i32::MAX] {
                (*entry).length = length;
                assert_eq!(virtual_indexed_payload_length(&mut fixture.object), length.max(0) as u32);
            }
            index.write(0);
            assert_eq!(virtual_indexed_payload_length(&mut fixture.object), 0);
        }
    }
}
