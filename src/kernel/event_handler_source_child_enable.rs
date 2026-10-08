//! Enables a child and publishes its bound node's value to the shared source.
//!
//! `FUN_08122220` @ `0x08122220`: true size 52 bytes, next real function
//! `0x08122254`. Raw A32 has one plain BL, zero predicated BLs, and one
//! outbound tail branch (not a second BL). Store halfword 1 at child+0x68,
//! snapshot the bound node pointer at +0x90, select node+0x30 or 0x7fff,
//! acquire the source, then publish the value through the 0x08038068 veneer.
//! That veneer targets 0x22007a68, the IRAM mirror of osos 0x08007a68:
//! update matching child slots and recompute the unsigned minimum, capped
//! at 0x7fff, at source+0x24. This unported body remains an exact-address
//! seam. Deliberate deviation: reuse the ported source getter rather than
//! its IRAM veneer; Rust may call/return instead of the original tail branch.

unsafe fn enable(child: *mut u8, source: impl FnOnce() -> *mut u8,
    publish: impl FnOnce(*mut u8, *mut u8, u32)) {
    child.add(0x68).cast::<u16>().write(1);
    let node = child.add(0x90).cast::<u32>().read();
    let value = if node == 0 { 0x7fff } else {
        (node as usize as *const u32).add(0x30 / 4).read()
    };
    let source = source();
    publish(source, child, value);
}

/// # Safety
/// `child` is an aligned writable retail-layout object through +0x93.
/// Its nonzero +0x90 word points to a readable node through +0x33; firmware
/// source services and the verified IRAM mirror must be initialized.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_handler_source_child_enable(child: *mut u8) {
    enable(child, || crate::kernel::event_handler_source::event_handler_source(),
        |source, child, value| {
            let publish: unsafe extern "C" fn(*mut u8, *mut u8, u32) =
                core::mem::transmute(0x2200_7a68usize);
            publish(source, child, value);
        });
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::EVENT_HANDLER_SOURCE_CHILD_ENABLE, 4096).map(|p| p as usize)
    });
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn enable_preserves_adjacent_halfword_and_defaults_without_node() {
        let mut child = [0xa5a5_a5a5u32; 0x94 / 4];
        child[0x90 / 4] = 0;
        let original = child;
        let ptr = child.as_mut_ptr().cast::<u8>();
        unsafe { enable(ptr, || {
            assert_eq!(ptr.add(0x68).cast::<u32>().read(), 0xa5a5_0001);
            core::ptr::null_mut()
        }, |_, _, value| assert_eq!(value, 0x7fff)); }
        child[0x68 / 4] = original[0x68 / 4];
        assert_eq!(child, original);
    }

    #[test]
    fn node_value_is_unclamped_and_snapshotted_before_source_acquisition() {
        let _guard = LOCK.lock();
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("kernel/event_handler_source_child_enable")); return;
        };
        unsafe {
            let node = base as *mut u32;
            let mut child = [0u32; 0x94 / 4];
            child[0x90 / 4] = base as u32;
            let ptr = child.as_mut_ptr().cast::<u8>();
            for value in [0, 1, 0x7fff, 0x8000, u32::MAX] {
                node.add(0x30 / 4).write(value);
                enable(ptr, || {
                    assert_eq!(ptr.add(0x68).cast::<u16>().read(), 1);
                    node.add(0x30 / 4).write(42);
                    ptr.add(0x90).cast::<u32>().write(0);
                    core::ptr::null_mut()
                }, |_, _, snapshot| assert_eq!(snapshot, value));
                child[0x90 / 4] = base as u32;
            }
        }
    }
}
