//! Resource count for a query object's backend.

use super::object_resource_count::object_resource_count;

/// query_object_resource_count — original: `FUN_0813d098` @ `0x0813d098`
/// (8 bytes; next real function starts at `0x0813d0a0`).
///
/// Raw words `e5900040 eafc5c36` decode to `ldr r0,[r0,#0x40];
/// b 0x0805417c`. Whole-image A32 decoding verifies two inbound plain BL
/// calls, at `0x08179ed0` and `0x0817a06c`, and no predicated BL callers.
/// The body has zero plain or predicated BL instructions and one tail branch.
///
/// Loads the query's target-width object pointer at `+0x40`, then returns
/// its kind-resolved backend resource count through `object_resource_count`.
/// The callers use this count as the bound for resource traversal.
/// Deliberate deviation: Rust expresses the tail branch as a returning call
/// to the existing port; pointer fields remain 32-bit on hosts. No validation
/// or count normalization is added.
///
/// # Safety
///
/// `query + 0x40` must be readable as an aligned `u32` containing an object
/// pointer satisfying [`object_resource_count`]'s safety requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn query_object_resource_count(query: *const u8) -> u32 {
    let object = query.add(0x40).cast::<u32>().read() as usize as *const u8;
    object_resource_count(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn preserves_counts_and_resolves_proxy_using_target_width_fields() {
        let Some(slab) = try_map_u32_slab(hints::QUERY_OBJECT_RESOURCE_COUNT, 0x4000) else {
            assert!(note_missing_u32_fixture("ui/query_object_resource_count"));
            return;
        };
        unsafe {
            let query = slab;
            let backend = slab.add(0x100);
            let proxy = slab.add(0x2000);
            backend.write(1);
            proxy.write(2);
            // The existing resolver models its proxy field as a host pointer.
            proxy.add(0xefc).cast::<*const u8>().write_unaligned(backend);
            // Adjacent nonzero word detects a host-width query pointer load.
            query.add(0x44).cast::<u32>().write(0xdead_beef);
            for object in [backend, proxy] {
                query.add(0x40).cast::<u32>().write(object as usize as u32);
                for count in [0, 1, 0x8000_0000, u32::MAX] {
                    backend.add(0xf68).cast::<u32>().write(count);
                    assert_eq!(query_object_resource_count(query), count);
                }
            }
        }
    }
}
