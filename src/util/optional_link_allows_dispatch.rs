//! Optional-link ownership and back-reference validation.
//!
//! Original `FUN_080dad3c` @ `0x080dad3c`, 72 bytes, true extent
//! `[0x080dad3c, 0x080dad84)`. Raw words verify zero outgoing plain or
//! predicated BLs; two incoming plain BLs, zero predicated BLs.
//! A null optional pair is accepted. Otherwise its first word must point to
//! a link whose first word equals the dispatcher. The second pair word must
//! be zero, UINT32_MAX, or point to a record whose second word is that link.
//! No deliberate behavioral deviations; aligned u32 word indexing preserves
//! the target's four-byte pointer fields on hosts as well as ARM.

/// All traversed non-sentinel target addresses must be aligned and readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn optional_link_allows_dispatch(dispatcher: u32, optional_link: *const u32) -> u32 {
    if optional_link.is_null() {
        return 1;
    }
    let link = optional_link.read();
    if link == 0 || (link as usize as *const u32).read() != dispatcher {
        return 0;
    }
    let association = optional_link.add(1).read();
    if association == 0 || association == u32::MAX {
        return 1;
    }
    ((association as usize as *const u32).add(1).read() == link) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ownership_and_association_matrix() {
        assert_eq!(unsafe { optional_link_allows_dispatch(0, core::ptr::null()) }, 1);
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::OPTIONAL_LINK_ALLOWS_DISPATCH, 4096,
        ) else { return; };
        unsafe {
            let link = slab.cast::<u32>();
            let association = link.add(4);
            let pair = link.add(8);
            for dispatcher in [0, 1, 0x0800_1234, u32::MAX] {
                for owner in [0, 1, 0x0800_1234, u32::MAX] {
                    link.write(owner);
                    for link_present in [false, true] {
                        let link_address = if link_present { link as usize as u32 } else { 0 };
                        pair.write(link_address);
                        // Invalid association addresses must not be traversed on
                        // ownership rejection; sentinels must never be dereferenced.
                        for tag in [0, u32::MAX, association as usize as u32] {
                            pair.add(1).write(tag);
                            for back_reference in [0, link as usize as u32, link as usize as u32 + 4] {
                                association.write(0xdead_beef);
                                association.add(1).write(back_reference);
                                let expected = (link_present && owner == dispatcher
                                    && (tag == 0 || tag == u32::MAX || back_reference == link_address)) as u32;
                                assert_eq!(optional_link_allows_dispatch(dispatcher, pair), expected);
                                assert_eq!(pair.read(), link_address);
                                assert_eq!(pair.add(1).read(), tag);
                                assert_eq!(link.read(), owner);
                                assert_eq!(association.add(1).read(), back_reference);
                            }
                        }
                    }
                }
            }
            pair.write(0);
            pair.add(1).write(1);
            assert_eq!(optional_link_allows_dispatch(1, pair), 0);
            pair.write(link as usize as u32);
            link.write(2);
            assert_eq!(optional_link_allows_dispatch(1, pair), 0);
        }
    }
}
