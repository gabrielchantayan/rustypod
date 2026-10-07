//! Query an item through an interface using a zero-based index.
//!
//! Original `FUN_0813c9dc` at `0x0813c9dc`: true size 16 bytes, ending
//! before the independent prologue at `0x0813c9ec`. Raw words are e5913000,
//! e2822001, e5933288, e12fff13. Whole-image A32 decoding verifies two
//! inbound plain BLs (0x0810c864, 0x0810c8d4), zero predicated inbound BLs,
//! and zero internal BLs. The final BX tail-dispatches vtable slot +0x288.
//! Callers iterate zero-based indices and inspect the output object. Add one
//! modulo 2^32 and invoke the unresolved virtual method with output, interface,
//! and the one-based index. Preserve its opaque r0 result, although both known
//! callers ignore it. No concrete callee identity is assumed.
//!
//! Deliberate deviations: repr(C) pointers and vtable entries widen on hosts;
//! target word indices are preserved. Rust expresses the tail dispatch as a
//! returning call. No validation or fixed-address callee seam is introduced.

#[repr(C)]
pub struct IndexedItemVtable {
    pub reserved: [usize; 0x288 / 4],
    pub query_one_based: unsafe extern "C" fn(*mut u8, *mut IndexedItemInterface, u32) -> u32,
}

#[repr(C)]
pub struct IndexedItemInterface {
    pub vtable: *const IndexedItemVtable,
}

/// # Safety
/// The interface must have a readable vtable with a callable +0x288 slot.
/// Output storage and the index must satisfy that virtual method's contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn indexed_item_query(
    output: *mut u8, interface: *mut IndexedItemInterface, index: u32,
) -> u32 {
    ((*(*interface).vtable).query_one_based)(output, interface, index.wrapping_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Collection {
        interface: IndexedItemInterface,
        items: [u32; 3],
        queries: u32,
    }

    unsafe extern "C" fn query(
        output: *mut u8, interface: *mut IndexedItemInterface, index: u32,
    ) -> u32 {
        let collection = &mut *interface.cast::<Collection>();
        collection.queries += 1;
        if (1..=3).contains(&index) {
            output.cast::<u32>().write(collection.items[(index - 1) as usize]);
            0
        } else {
            0x8000_0000 | index
        }
    }

    #[test]
    fn selects_items_and_preserves_failure_output_at_wrapping_boundaries() {
        let vtable = IndexedItemVtable { reserved: [0; 0x288 / 4], query_one_based: query };
        let mut collection = Collection {
            interface: IndexedItemInterface { vtable: &vtable },
            items: [0x1234_5678, 0, u32::MAX], queries: 0,
        };
        for (index, expected_output, expected_result) in [
            (0, 0x1234_5678, 0), (1, 0, 0), (2, u32::MAX, 0),
            (3, 0x5555_aaaa, 0x8000_0004),
            (0x7fff_ffff, 0x5555_aaaa, 0x8000_0000),
            (u32::MAX, 0x5555_aaaa, 0x8000_0000),
        ] {
            let mut output = [0x1111_2222u32, 0x5555_aaaa, 0x3333_4444];
            let result = unsafe {
                indexed_item_query(output.as_mut_ptr().add(1).cast(), &mut collection.interface, index)
            };
            assert_eq!(result, expected_result);
            assert_eq!(output, [0x1111_2222, expected_output, 0x3333_4444]);
            assert_eq!(collection.items, [0x1234_5678, 0, u32::MAX]);
        }
        assert_eq!(collection.queries, 6);
    }
}
