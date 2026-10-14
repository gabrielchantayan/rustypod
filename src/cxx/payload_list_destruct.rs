//! Payload-list destruction — `FUN_083dc640` @ `0x083dc640`.
//! True size: 212 bytes, ending at the next prologue at `0x083dc714`.
//! Raw A32: four outgoing plain BLs (erase, compare, two deallocations),
//! one incoming plain BL at `0x0811f554`; no predicated BLs.
//! Erase live nodes up to the initially captured sentinel, reload and recycle
//! the sentinel, unlink each pool chunk before freeing its arena and record,
//! clear the three pool cursors, and return the input list. Null sentinel is
//! a complete no-op. Target pointer fields remain aligned four-byte words.
//! Deliberate deviations: comparison is inlined; erase uses retail 0x083dc3fc
//! because the existing Rust erase port adds an extra release-target dereference.

type Erase = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32);
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_erase(out: *mut u32, list: *mut u32, cursor: *mut u32) {
    let erase: Erase = core::mem::transmute(0x083d_c3fcusize);
    erase(out, list, cursor);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_erase(_: *mut u32, _: *mut u32, _: *mut u32) {
    panic!("payload_list_destruct requires retail payload-list erase");
}

/// # Safety
/// `list` holds six aligned target words and owns valid sentinel, nodes,
/// payload release handles, and pool allocations accepted by the retail heap.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn payload_list_destruct(list: *mut u32) -> *mut u32 {
    destruct_with(list, retail_erase, |ptr, count, elem| {
        crate::heap::veneers::cxx_array_dealloc(ptr, count, elem)
    })
}

#[inline(always)]
unsafe fn destruct_with(list: *mut u32, erase: Erase,
    mut dealloc: impl FnMut(*mut u8, usize, usize)) -> *mut u32 {
    let sentinel = list.add(4).read();
    if sentinel != 0 {
        let mut cursor = (sentinel as usize as *mut u32).read();
        while cursor != sentinel {
            let mut input = cursor;
            erase(&mut cursor, list, &mut input);
        }
        let sentinel = list.add(4).read();
        (sentinel as usize as *mut u32).write(list.add(1).read());
        list.add(1).write(sentinel);
        while list.read() != 0 {
            let chunk = list.read() as usize as *mut u32;
            list.write(chunk.read());
            dealloc(chunk.add(2).read() as usize as *mut u8, chunk.add(1).read() as usize, 0);
            dealloc(chunk.cast(), 1, 0);
        }
        list.add(1).write(0);
        list.add(2).write(0);
        list.add(3).write(0);
    }
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_sentinel_preserves_every_word_and_returns_owner() {
        let mut list = [11, 13, 17, 19, 0, 23];
        unsafe { assert_eq!(payload_list_destruct(list.as_mut_ptr()), list.as_mut_ptr()); }
        assert_eq!(list, [11, 13, 17, 19, 0, 23]);
    }

    unsafe extern "C" fn erase_reference(out: *mut u32, list: *mut u32, cursor: *mut u32) {
        let node = cursor.read() as usize as *mut u32;
        let next = node.read();
        let previous = node.add(1).read() as usize as *mut u32;
        previous.write(next);
        (next as usize as *mut u32).add(1).write(previous as usize as u32);
        list.add(5).write(list.add(5).read().wrapping_sub(1));
        // Model the observable payload release before recycling the node.
        node.add(2).write(0);
        node.write(list.add(1).read());
        list.add(1).write(node as usize as u32);
        out.write(next);
    }

    #[test]
    fn empty_and_live_rings_recycle_sentinel_and_drain_multiple_chunks_in_order() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::PAYLOAD_LIST_DESTRUCT, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("payload_list_destruct"));
            return;
        };
        unsafe {
            for count in [0u32, 2] {
                let sentinel = slab.add(0x40).cast::<u32>();
                let first = slab.add(0x80).cast::<u32>();
                let second = slab.add(0xa0).cast::<u32>();
                let chunks = [slab.add(0xc0).cast::<u32>(), slab.add(0xe0).cast::<u32>()];
                let arenas = [slab.add(0x200), slab.add(0x300)];
                sentinel.write(if count == 0 { sentinel } else { first } as usize as u32);
                sentinel.add(1).write(if count == 0 { sentinel } else { second } as usize as u32);
                first.write(second as usize as u32);
                first.add(1).write(sentinel as usize as u32);
                second.write(sentinel as usize as u32);
                second.add(1).write(first as usize as u32);
                first.add(2).write(71);
                second.add(2).write(73);
                for i in 0..2 {
                    chunks[i].write(if i == 0 { chunks[1] as usize as u32 } else { 0 });
                    chunks[i].add(1).write(32 + i as u32);
                    chunks[i].add(2).write(arenas[i] as usize as u32);
                }
                let mut list = [chunks[0] as usize as u32, 0, 11, 13, sentinel as usize as u32, count];
                let owner = list.as_mut_ptr();
                let mut frees = 0;
                assert_eq!(destruct_with(owner, erase_reference, |ptr, capacity, elem| {
                    let i = frees / 2;
                    assert_eq!(owner.read(), if i == 0 { chunks[1] as usize as u32 } else { 0 });
                    assert_eq!(owner.add(5).read(), 0);
                    assert_eq!(owner.add(1).read(), sentinel as usize as u32);
                    assert_eq!(sentinel.read(), if count == 0 { 0 } else { second as usize as u32 });
                    if count != 0 {
                        assert_eq!(first.add(2).read(), 0);
                        assert_eq!(second.add(2).read(), 0);
                        assert_eq!(second.read(), first as usize as u32);
                    }
                    assert_eq!((ptr, capacity, elem), if frees % 2 == 0 {
                        (arenas[i], 32 + i, 0)
                    } else { (chunks[i].cast(), 1, 0) });
                    if frees % 2 == 1 { chunks[i].write(u32::MAX); }
                    frees += 1;
                }), owner);
                assert_eq!(frees, 4);
                assert_eq!(list, [0, 0, 0, 0, sentinel as usize as u32, 0]);
            }
        }
    }
}
