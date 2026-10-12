//! 'plst' task completion, message dispatch, and resource reset.

use super::plst_task_resource_callback::plst_task_resource_callback;
use super::plst_resource_dispatch_pldm::plst_resource_dispatch_pldm;
use super::plst_resource_reset::plst_resource_reset;

/// plst_resource_dispatch_and_reset — original: `FUN_08048204` @ `0x08048204`.
/// True extent: 44 instruction bytes, ending at the independently entered
/// push-prologue at `0x08048230`. Raw words verify three plain BL calls
/// (`0x0805cde4`, `0x080487ac`, `0x0806c16c`), zero predicated BL calls.
/// Complete the task stored in element+0x40, dispatch `pldm` for the element,
/// then reset its resource even when dispatch returns an error. Return the
/// saved dispatch status, not any result from completion or reset.
/// Deliberate deviations: none; all three callees use their existing ports.
/// ARM match review: LLVM adds a frame-pointer instruction (12 versus 11
/// instructions); relocations retain the three direct callees in stock order.
///
/// # Safety
/// `element` must be non-NULL, aligned, and readable through +0x43. Its
/// target-width task pointer at +0x40 must satisfy `plst_task_resource_callback`.
/// The element must also satisfy `plst_resource_dispatch_pldm` and
/// `plst_resource_reset`, including after either earlier call mutates it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plst_resource_dispatch_and_reset(element: *mut u32) -> u32 {
    let task = element.add(0x40 / 4).read() as usize as *mut u32;
    plst_task_resource_callback(task);
    let status = plst_resource_dispatch_pldm(element.cast());
    plst_resource_reset(element);
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    #[test]
    fn rejected_element_still_completes_active_task_and_preserves_error() {
        let base = try_map_u32_slab(hints::PLST_RESOURCE_DISPATCH_AND_RESET, 0x1000)
            .expect("target-width dispatch-and-reset fixture");
        unsafe {
            base.write_bytes(0, 0x1000);
            let element = base.cast::<u32>();
            let task = base.add(0x200).cast::<u32>();
            let linked_element = base.add(0x400).cast::<u32>();
            linked_element.add(1).write(0x706c_7374);
            task.write(linked_element as usize as u32);
            element.add(0x40 / 4).write(task as usize as u32);
            // Invalid outer class rejects dispatch/reset, independently of
            // the task's own valid 'plst' link and activity flag.
            for active in [0, 1, u32::MAX] {
                task.add(4).write(active);
                task.add(5).write(0xdead_beef);
                task.add(6).write(0xaabb_ccdd);
                assert_eq!(plst_resource_dispatch_and_reset(element), 0xffff_ffce);
                assert_eq!(task.add(5).read(), if active == 0 { 0xdead_beef } else { 1 });
                assert_eq!(task.add(6).read(), 0xaabb_ccdd);
                assert_eq!(element.add(0x40 / 4).read(), task as usize as u32);
            }
            // NULL task is valid; NULL outer element is not.
            element.add(0x40 / 4).write(0);
            assert_eq!(plst_resource_dispatch_and_reset(element), 0xffff_ffce);
            assert_eq!(task.add(5).read(), 1);
        }
    }
}
