//! Linked 'plst' item music-path resolution.

/// ui_plst_linked_item_music_path — retailOS `FUN_08053114` @ `0x08053114`.
/// True extent: 92 bytes, `0x08053114..0x08053170`, including the -65536
/// literal at +0x58; the next function starts with push at 0x08053170.
/// Raw words verify two plain body BLs, no predicated BLs, and two inbound
/// plain BLs at 0x081a31a8 and 0x081a4c8c (no predicated callers).
///
/// Reject NULL output with -50 before reading owner. Fetch selector 1's
/// forward item from *(owner+0xf50); return -65536 if absent. Follow its
/// +0x20 record link and require byte +0x16 == 1, otherwise return -43.
/// Resolve the inline path at record+0xc0 into the volume-prefixed output,
/// deliberately discard the resolver's status, and return zero.
///
/// Deliberate deviations: call existing Rust ports directly. Supply zero
/// for the resolver's reserved/seed words: stock does not establish those
/// caller-saved registers after item lookup, and the volume matcher writes
/// the digit before its successful branch consumes it.
///
/// # Safety
/// For non-NULL output, owner must have a readable aligned u32 at +0xf50.
/// Its target-width element/item/record links must satisfy the slot lookup
/// and music_path_resolve contracts. Output holds a u16 header plus the
/// resulting NUL-terminated path (retail callers allocate 260 bytes).
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_plst_linked_item_music_path(
    owner: *const u8, index: u32, output: *mut u16,
) -> i32 {
    if output.is_null() {
        return -50;
    }
    let element = owner.add(0xf50).cast::<u32>().read() as usize as *mut u8;
    let item = super::plst_slot_item::ui_plst_slot_item_at(element, 1, 0, index)
        as usize as *const u8;
    if item.is_null() {
        return -65536;
    }
    let record = item.add(0x20).cast::<u32>().read() as usize as *const u8;
    if record.add(0x16).read() != 1 {
        return -43;
    }
    let _ = crate::fs::music_path_resolve::music_path_resolve(record.add(0xc0), output, 0, 0);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use crate::testing::{hints, try_map_u32_slab, note_missing_u32_fixture};

    #[test]
    fn rejects_without_writes_and_resolves_only_kind_one() {
        unsafe {
            assert_eq!(ui_plst_linked_item_music_path(ptr::null(), 0, ptr::null_mut()), -50);
            let Some(owner) = try_map_u32_slab(hints::PLST_LINKED_ITEM_MUSIC_PATH, 0x6000) else {
                assert!(note_missing_u32_fixture("ui/plst_music_path"));
                return;
            };
            ptr::write_bytes(owner, 0, 0x6000);
            let element = owner.add(0x1000);
            let header = owner.add(0x2000);
            let slot = owner.add(0x3000);
            let item = owner.add(0x4000);
            let record = owner.add(0x4100);
            owner.add(0xf50).cast::<u32>().write(element as usize as u32);
            element.add(4).cast::<u32>().write(0x706c7374);
            element.add(0x40).cast::<u32>().write(header as usize as u32);
            header.add(0x2e).cast::<u16>().write(2);
            element.add(0x3b0).cast::<u32>().write(slot as usize as u32);
            slot.add(0x14).cast::<u32>().write(item as usize as u32);
            item.add(0x20).cast::<u32>().write(record as usize as u32);
            let mut output = [0xa55au16; 130];
            for index in [0, 2, u32::MAX] {
                assert_eq!(ui_plst_linked_item_music_path(owner, index, output.as_mut_ptr()), -65536);
                assert_eq!(output, [0xa55a; 130]);
            }
            for kind in [0, 2, 255] {
                record.add(0x16).write(kind);
                assert_eq!(ui_plst_linked_item_music_path(owner, 1, output.as_mut_ptr()), -43);
                assert_eq!(output, [0xa55a; 130]);
            }
            record.add(0x16).write(1);
            let path = record.add(0xc0);
            path.add(0x24).write(1); // Use the resolver's real prefix branch.
            for source in [b"F00/song.mp3\0".as_slice(), b"\0".as_slice()] {
                ptr::copy_nonoverlapping(source.as_ptr(), path, source.len());
                output.fill(0xa55a);
                assert_eq!(ui_plst_linked_item_music_path(owner, 1, output.as_mut_ptr()), 0);
                assert_eq!(output[0], 0);
                let bytes = core::slice::from_raw_parts(output.as_ptr().cast::<u8>(), 260);
                let prefix = b"iPod_Control\\Music\\";
                assert_eq!(&bytes[2..2 + prefix.len()], prefix);
                assert_eq!(&bytes[2 + prefix.len()..2 + prefix.len() + source.len()], source);
                assert!(bytes[2 + prefix.len() + source.len()..].iter().all(|&b| b == 0x5a || b == 0xa5));
            }
        }
    }
}
