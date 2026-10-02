//! First matching byte-tag lookup in an embedded indexed collection.
//!
//! Original `FUN_082988ec` @ **0x082988ec**, true size **68 bytes**:
//! 0x082988ec..0x08298930, where the next real function starts. Raw A32
//! decoding finds two inbound plain BLs (0x081241b8, 0x081241d4), no
//! predicated inbound BLs; one outbound plain BL to 0x083d6ad4 and no
//! predicated outbound BLs.
//!
//! Capture the signed count at owner +0x58, then visit indices [0,count)
//! through the collection at +0x54. Return the first element whose byte at
//! +0x3a equals the full u32 query, or NULL. Zero/negative counts skip all
//! dispatch; queries above 255 never match. Count is not reloaded after
//! callbacks. No element NULL checks are added.
//!
//! Deliberate deviation: a repr(C) prefix widens the collection vtable
//! pointer on hosts, moving count accordingly; ARM retains +0x54/+0x58.
//! Reuse the verified indexed result-word wrapper, not an invented callee.

use crate::cxx::vtable_slot_40_result_word_at_alt::vtable_slot_40_result_word_at_alt;

#[repr(C)]
pub struct ByteTagCollectionOwner {
    pub opaque_prefix: [u32; 21],
    pub collection_vtable: *const u8,
    pub count: i32,
}

/// # Safety
/// `owner` must be readable. For every visited index, its embedded collection
/// must support slot +0x40 dispatch returning a readable u32 element address;
/// that address must point to an object readable through byte +0x3a.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn collection_find_byte_tag(
    owner: *mut ByteTagCollectionOwner, tag: u32,
) -> *mut u8 {
    let count = unsafe { core::ptr::addr_of!((*owner).count).read() };
    let collection = unsafe { core::ptr::addr_of_mut!((*owner).collection_vtable).cast::<u8>() };
    let mut index = 0i32;
    while index < count {
        let element = unsafe { vtable_slot_40_result_word_at_alt(collection, index as u32) }
            as usize as *mut u8;
        if unsafe { element.add(0x3a).read() } as u32 == tag {
            return element;
        }
        index += 1;
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    type Method = unsafe extern "C" fn(*mut u8, u32) -> *const u32;
    #[repr(C)]
    struct Collection {
        vtable: *const Method,
        count: i32,
        elements: [u32; 4],
        mutate_count: bool,
        visited: u32,
    }
    #[repr(C)]
    struct Fixture {
        prefix: [u32; 21],
        collection: Collection,
    }
    unsafe extern "C" fn at(receiver: *mut u8, index: u32) -> *const u32 {
        let collection = unsafe { &mut *receiver.cast::<Collection>() };
        collection.visited |= 1 << index;
        if collection.mutate_count { collection.count = 0; }
        core::ptr::addr_of!(collection.elements[index as usize])
    }

    #[test]
    fn signed_bounds_first_match_full_width_query_and_captured_count() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::COLLECTION_FIND_BYTE_TAG, 4096,
        ) else { return; };
        let vtable = [at as Method; 17];
        let elements = core::array::from_fn::<_, 4, _>(|index| unsafe {
            let element = slab.add(index * 64);
            element.add(0x3a).write([0, 255, 255, 7][index]);
            element as usize as u32
        });
        let mut fixture = Fixture {
            prefix: [0; 21],
            collection: Collection {
                vtable: vtable.as_ptr(), count: 4, elements,
                mutate_count: false, visited: 0,
            },
        };
        let owner = (&mut fixture as *mut Fixture).cast::<ByteTagCollectionOwner>();
        for count in [i32::MIN, -1, 0, 1, 2, 3, 4] {
            for tag in [0, 7, 42, 255, 256, u32::MAX] {
                fixture.collection.count = count;
                fixture.collection.visited = 0;
                let tags = [0u32, 255, 255, 7];
                let found = (0..count.max(0) as usize).find(|&i| tags[i] == tag);
                let expected = found.map_or(core::ptr::null_mut(), |i| elements[i] as usize as *mut u8);
                assert_eq!(unsafe { collection_find_byte_tag(owner, tag) }, expected,
                    "count={count}, tag={tag}");
                let visited = found.map_or(count.max(0) as u32, |i| i as u32 + 1);
                assert_eq!(fixture.collection.visited, (1 << visited) - 1);
            }
        }
        fixture.collection.count = 4;
        fixture.collection.mutate_count = true;
        fixture.collection.visited = 0;
        assert_eq!(unsafe { collection_find_byte_tag(owner, 7) }, elements[3] as usize as *mut u8);
        assert_eq!(fixture.collection.visited, 15);
        assert_eq!(fixture.collection.count, 0);
    }
}
