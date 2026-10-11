//! Validated successor link for a container attached to a `'liti'` database.

use crate::app::nested_liti_class_check::nested_liti_class_check;

/// `liti_container_successor` — original: `FUN_08053ba0` @ `0x08053ba0`
/// (24 bytes; two inbound plain BL calls, zero predicated BL).
///
/// Raw extent: `0x08053ba0..0x08053bb8`; the next function starts with
/// `mov r2, r0` at `0x08053bb8`. The six words decode as:
///
/// ```text
/// 08053ba0  mov r2, r0
/// 08053ba4  push {lr}
/// 08053ba8  bl 0x08057bdc       ; nested_liti_class_check
/// 08053bac  movs r0, r0
/// 08053bb0  ldrne r0, [r2]
/// 08053bb4  pop {pc}
/// ```
///
/// Algorithm: validate the container's +0x08 target-width pointer as a
/// `'liti'` database, then return the container's word-zero successor link;
/// return zero for a NULL container, NULL database, or rejected class tag.
/// Callers at 0x0805e350 and 0x08064120 advance container-list traversals.
/// The body has one plain BL and no predicated BL. Counts were independently
/// verified by decoding raw ARM words, not Ghidra's function references.
///
/// Deliberate deviations: call the existing Rust class-check port rather than
/// stock firmware; otherwise none. The link remains an opaque u32 and is not
/// dereferenced or widened to a host pointer.
///
/// # Safety
///
/// `container` may be NULL. Otherwise it must be four-byte aligned and
/// readable through +0x0b, and its +0x08 word must meet
/// [`nested_liti_class_check`]'s pointer validity requirements.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.liti_container_successor")]
pub unsafe extern "C" fn liti_container_successor(container: *const u8) -> u32 {
    if unsafe { nested_liti_class_check(container) } != 0 {
        unsafe { container.cast::<u32>().read() }
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static FIXTURE: std::sync::LazyLock<Option<usize>> = std::sync::LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::LITI_CONTAINER_SUCCESSOR,
            0x1000,
        ).map(|pointer| pointer as usize)
    });

    #[test]
    fn null_container_returns_zero() {
        assert_eq!(unsafe { liti_container_successor(core::ptr::null()) }, 0);
    }

    #[test]
    fn validation_gates_word_zero_without_following_the_link() {
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(crate::testing::note_missing_u32_fixture("app::liti_container_successor"));
            return;
        };
        unsafe {
            core::ptr::write_bytes(base as *mut u8, 0, 0x1000);
            let container = (base + 0x100) as *mut u32;
            let database = (base + 0x200) as *mut u32;
            container.add(1).write(0x1234_5678);
            for link in [0, 1, 0x0805_0000, 0x2200_0000, u32::MAX] {
                container.write(link);
                container.add(2).write(0);
                assert_eq!(liti_container_successor(container.cast()), 0);
                container.add(2).write(database as usize as u32);
                for tag in [0, 0x706c_7374, 0x6974_696c, u32::MAX] {
                    database.write(tag);
                    let expected = if tag == 0x6974_696c { link } else { 0 };
                    assert_eq!(liti_container_successor(container.cast()), expected);
                }
            }
        }
    }
}
