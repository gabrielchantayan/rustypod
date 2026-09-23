//! Destruction and deallocation of an owned two-word pair.

use crate::heap::veneers::{operator_delete, operator_delete_tag3};

/// owned_pair_destroy_and_deallocate — original `FUN_081d85e8` @ 0x081d85e8
/// (44 bytes, not Ghidra's 28-byte extent): two internal plain `bl` calls;
/// three direct incoming calls, two plain `bl` and one predicated `bleq`.
///
/// The word at `owner+8` is the pair pointer. A zero pair leaves the owner
/// untouched. Otherwise, retailOS destroys the pair by deleting its second
/// word with tag 3, clears both pair words, deletes the pair itself with tag
/// 2, then clears owner words +8 and +4. Raw ARM continues past Ghidra's
/// premature boundary through `mov r0,#0; str r0,[r4,#8]; str r0,[r4,#4];
/// ldmia sp!,{r4,pc}` @ 0x081d8604..0x081d8610. There are no deliberate
/// deviations; word accesses retain the target's four-byte field layout on
/// hosts with wider native pointers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn owned_pair_destroy_and_deallocate(owner: *mut u8) {
    let pair = owner.add(8).cast::<u32>().read() as usize as *mut u8;
    if pair.is_null() {
        return;
    }

    let resource = pair.add(4).cast::<u32>().read() as usize as *mut u8;
    operator_delete_tag3(resource);
    pair.add(4).cast::<u32>().write(0);
    pair.cast::<u32>().write(0);
    operator_delete(pair);
    owner.add(8).cast::<u32>().write(0);
    owner.add(4).cast::<u32>().write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;

    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::OWNED_PAIR_DESTROY_AND_DEALLOCATE, 0x1000)
            .map(|pointer| pointer as usize)
    });

    fn fixture() -> Option<*mut u32> {
        (*FIXTURE).map(|pointer| pointer as *mut u32)
    }

    #[test]
    fn null_pair_leaves_owner_and_heap_untouched() {
        let _lock = mock_heap();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("heap/owned_pair_destroy_and_deallocate"));
            return;
        };
        unsafe {
            owner.add(0).write(0x1111_1111);
            owner.add(1).write(0x2222_2222);
            owner.add(2).write(0);
            owner.add(3).write(0x4444_4444);
            owned_pair_destroy_and_deallocate(owner.cast());
            assert_eq!([owner.read(), owner.add(1).read(), owner.add(2).read(), owner.add(3).read()], [0x1111_1111, 0x2222_2222, 0, 0x4444_4444]);
        }
        assert_eq!(free_log().0, 0);
    }

    #[test]
    fn destroys_pair_resource_then_clears_and_deletes_pair() {
        let _lock = mock_heap();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("heap/owned_pair_destroy_and_deallocate"));
            return;
        };
        let pair = unsafe { owner.add(4) };
        unsafe {
            pair.write(0xaaaa_aaaa);
            pair.add(1).write(0x1234_5000);
            owner.write(0x1111_1111);
            owner.add(1).write(0x2222_2222);
            owner.add(2).write(pair as usize as u32);
            owner.add(3).write(0x4444_4444);
            owned_pair_destroy_and_deallocate(owner.cast());
            assert_eq!([pair.read(), pair.add(1).read()], [0, 0]);
            assert_eq!([owner.read(), owner.add(1).read(), owner.add(2).read(), owner.add(3).read()], [0x1111_1111, 0, 0, 0x4444_4444]);
        }
        let (calls, pointer, tag) = free_log();
        assert_eq!(calls, 2);
        assert_eq!(pointer, pair.cast());
        assert_eq!(tag, 2);
    }

    #[test]
    fn null_pair_resource_skips_tag3_delete_but_deletes_pair() {
        let _lock = mock_heap();
        let Some(owner) = fixture() else {
            assert!(note_missing_u32_fixture("heap/owned_pair_destroy_and_deallocate"));
            return;
        };
        let pair = unsafe { owner.add(4) };
        unsafe {
            pair.write(0xaaaa_aaaa);
            pair.add(1).write(0);
            owner.write(0);
            owner.add(1).write(0x2222_2222);
            owner.add(2).write(pair as usize as u32);
            owner.add(3).write(0);
            owned_pair_destroy_and_deallocate(owner.cast());
        }
        assert_eq!(free_log(), (1, pair.cast(), 2));
    }
}
