//! Region-list destruction — `FUN_083dcdbc` @ `0x083dcdbc`.
//! True size: 212 bytes, ending at the next prologue at `0x083dce90`.
//! Raw A32: four outgoing plain BLs (erase, compare, two deallocations),
//! one inbound plain BL at `0x081a801c`; no predicated BLs.
//! Erase live nodes to the sentinel, cache the sentinel, release each pool
//! arena then its record, and clear pool cursors. Return the original list.
//! Deliberate deviations: comparison is inlined. Erase remains the verified
//! retail boundary: the existing Rust erase port returns the wrong cursor
//! and targets delete rather than the raw region-element destructor.

type Erase = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32);
#[cfg(target_os = "none")]
unsafe extern "C" fn retail_erase(output: *mut u32, list: *mut u32, cursor: *mut u32) {
    let erase: Erase = core::mem::transmute(0x083d_cd38usize);
    erase(output, list, cursor);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_erase(_: *mut u32, _: *mut u32, _: *mut u32) {
    panic!("region_list_destruct requires the retail region-list erase boundary");
}

/// # Safety
/// `list` must contain six aligned target words and valid linked nodes,
/// sentinel, and pool allocations owned by the retail allocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn region_list_destruct(list: *mut u32) -> *mut u32 {
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
        while cursor != list.add(4).read() {
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
    fn null_sentinel_preserves_all_pool_state() {
        let mut list = [17, 23, 31, 47, 0, 59];
        unsafe { assert_eq!(region_list_destruct(list.as_mut_ptr()), list.as_mut_ptr()); }
        assert_eq!(list, [17, 23, 31, 47, 0, 59]);
    }

    unsafe extern "C" fn erase_reference(out: *mut u32, list: *mut u32, cursor: *mut u32) {
        let node = cursor.read() as usize as *mut u32;
        let next = node.read();
        let previous = node.add(1).read();
        (previous as usize as *mut u32).write(next);
        (next as usize as *mut u32).add(1).write(previous);
        list.add(5).write(list.add(5).read().wrapping_sub(1));
        node.write(list.add(1).read());
        list.add(1).write(node as usize as u32);
        out.write(next);
    }

    #[test]
    fn live_nodes_then_chunks_are_unlinked_before_free_and_cursors_cleared() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::REGION_LIST_DESTRUCT, 0x1000,
        ) else {
            assert!(crate::testing::note_missing_u32_fixture("region_list_destruct"));
            return;
        };
        unsafe {
            let sentinel = slab.add(0x40).cast::<u32>();
            let node = slab.add(0x80).cast::<u32>();
            let chunk = slab.add(0xc0).cast::<u32>();
            let arena = slab.add(0x100);
            sentinel.write(node as usize as u32);
            sentinel.add(1).write(node as usize as u32);
            node.write(sentinel as usize as u32);
            node.add(1).write(sentinel as usize as u32);
            chunk.write(0);
            chunk.add(1).write(32);
            chunk.add(2).write(arena as usize as u32);
            let mut list = [chunk as usize as u32, 0, 11, 13, sentinel as usize as u32, 1];
            let owner = list.as_mut_ptr();
            let mut frees = 0;
            assert_eq!(destruct_with(owner, erase_reference, |ptr, count, elem| {
                assert_eq!(owner.read(), 0);
                assert_eq!(owner.add(5).read(), 0);
                assert_eq!(sentinel.read(), node as usize as u32);
                assert_eq!(owner.add(1).read(), sentinel as usize as u32);
                assert_eq!((ptr, count, elem), if frees == 0 { (arena, 32, 0) } else { (chunk.cast(), 1, 0) });
                if frees == 1 { chunk.write(u32::MAX); }
                frees += 1;
            }), owner);
            assert_eq!(frees, 2);
            assert_eq!(list, [0, 0, 0, 0, sentinel as usize as u32, 0]);
        }
    }
}
