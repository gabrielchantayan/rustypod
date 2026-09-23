//! `transition_page_reset_animation_targets` — original: `FUN_08152478` @
//! 0x08152478 (128 bytes, 0x08152478..0x081524f8; **3 direct call sites:
//! 3 unconditional `bl`, 0 predicated**). The next real function begins at
//! 0x081524f8 with `push {r4, lr}`.
//!
//! Copies each of six default scalar values from the page's indirect source
//! records into its six 0x18-byte animation-target slots. Each source pointer
//! is loaded from the shared context at +0x34..+0x48; its +0x04 word becomes
//! the corresponding target slot's +0x0c value, and that slot's +0x10 word is
//! cleared. The six target slots start at +0x0c and have a 0x18-byte stride.
//!
//! Deliberate deviations: the retailOS object layouts have not been recovered
//! as Rust types, so this port uses explicit 32-bit target-layout offsets and
//! volatile accesses. It does not add NULL or alignment checks.

const SHARED_CONTEXT_OFFSET: usize = 0x128;
const SOURCE_RECORD_POINTER_OFFSET: usize = 0x34;
const SOURCE_RECORD_COUNT: usize = 6;
const TARGET_SLOT_OFFSET: usize = 0x0c;
const TARGET_SLOT_STRIDE: usize = 0x18;
const TARGET_VALUE_OFFSET: usize = 0;
const TARGET_AUX_OFFSET: usize = 4;
const RECORD_VALUE_OFFSET: usize = 4;

/// Initializes the six animation-target values embedded in `page` from its
/// shared context's default records. `page` must be a readable/writable
/// 32-bit-target-layout retailOS page whose indirect records are readable.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn transition_page_reset_animation_targets(page: *mut u8) {
    let record = core::ptr::read_volatile(page.add(SHARED_CONTEXT_OFFSET).cast::<u32>()) as usize as *const u8;
    let value = core::ptr::read_volatile((core::ptr::read_volatile(record.add(0x34).cast::<u32>()) as usize as *const u8).add(RECORD_VALUE_OFFSET).cast::<u32>());
    core::ptr::write_volatile(page.add(0x0c).cast::<u32>(), value);
    core::ptr::write_volatile(page.add(0x10).cast::<u32>(), 0);

    let record = core::ptr::read_volatile(page.add(SHARED_CONTEXT_OFFSET).cast::<u32>()) as usize as *const u8;
    let value = core::ptr::read_volatile((core::ptr::read_volatile(record.add(0x38).cast::<u32>()) as usize as *const u8).add(RECORD_VALUE_OFFSET).cast::<u32>());
    core::ptr::write_volatile(page.add(0x28).cast::<u32>(), 0);
    core::ptr::write_volatile(page.add(0x24).cast::<u32>(), value);

    let record = core::ptr::read_volatile(page.add(SHARED_CONTEXT_OFFSET).cast::<u32>()) as usize as *const u8;
    let value = core::ptr::read_volatile((core::ptr::read_volatile(record.add(0x3c).cast::<u32>()) as usize as *const u8).add(RECORD_VALUE_OFFSET).cast::<u32>());
    core::ptr::write_volatile(page.add(0x40).cast::<u32>(), 0);
    core::ptr::write_volatile(page.add(0x3c).cast::<u32>(), value);

    let record = core::ptr::read_volatile(page.add(SHARED_CONTEXT_OFFSET).cast::<u32>()) as usize as *const u8;
    let value = core::ptr::read_volatile((core::ptr::read_volatile(record.add(0x40).cast::<u32>()) as usize as *const u8).add(RECORD_VALUE_OFFSET).cast::<u32>());
    core::ptr::write_volatile(page.add(0x58).cast::<u32>(), 0);
    core::ptr::write_volatile(page.add(0x54).cast::<u32>(), value);

    let record = core::ptr::read_volatile(page.add(SHARED_CONTEXT_OFFSET).cast::<u32>()) as usize as *const u8;
    let value = core::ptr::read_volatile((core::ptr::read_volatile(record.add(0x44).cast::<u32>()) as usize as *const u8).add(RECORD_VALUE_OFFSET).cast::<u32>());
    core::ptr::write_volatile(page.add(0x70).cast::<u32>(), 0);
    core::ptr::write_volatile(page.add(0x6c).cast::<u32>(), value);

    let record = core::ptr::read_volatile(page.add(SHARED_CONTEXT_OFFSET).cast::<u32>()) as usize as *const u8;
    let value = core::ptr::read_volatile((core::ptr::read_volatile(record.add(0x48).cast::<u32>()) as usize as *const u8).add(RECORD_VALUE_OFFSET).cast::<u32>());
    core::ptr::write_volatile(page.add(0x84).cast::<u32>(), value);
    core::ptr::write_volatile(page.add(0x88).cast::<u32>(), 0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn it_copies_all_six_default_values_and_clears_only_their_aux_words() {
        let Some(slab) = try_map_u32_slab(hints::TRANSITION_PAGE_RESET_ANIMATION_TARGETS, 0x1000) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            let page = slab;
            let context = slab.add(0x200);
            page.add(SHARED_CONTEXT_OFFSET).cast::<u32>().write(context as usize as u32);
            for index in 0..SOURCE_RECORD_COUNT {
                let record = slab.add(0x300 + index * 8);
                record.add(RECORD_VALUE_OFFSET).cast::<u32>().write(0x1000_0000 | index as u32);
                context.add(SOURCE_RECORD_POINTER_OFFSET + index * 4).cast::<u32>().write(record as usize as u32);

                let target = page.add(TARGET_SLOT_OFFSET + index * TARGET_SLOT_STRIDE);
                target.sub(4).cast::<u32>().write(0xaaaa_0000 | index as u32);
                target.cast::<u32>().write(0xbbbb_0000 | index as u32);
                target.add(TARGET_AUX_OFFSET).cast::<u32>().write(0xcccc_0000 | index as u32);
                target.add(8).cast::<u32>().write(0xdddd_0000 | index as u32);
            }

            transition_page_reset_animation_targets(page);

            for index in 0..SOURCE_RECORD_COUNT {
                let target = page.add(TARGET_SLOT_OFFSET + index * TARGET_SLOT_STRIDE);
                assert_eq!(target.sub(4).cast::<u32>().read(), 0xaaaa_0000 | index as u32, "slot {index} preceding word");
                assert_eq!(target.cast::<u32>().read(), 0x1000_0000 | index as u32, "slot {index} value");
                assert_eq!(target.add(TARGET_AUX_OFFSET).cast::<u32>().read(), 0, "slot {index} aux");
                assert_eq!(target.add(8).cast::<u32>().read(), 0xdddd_0000 | index as u32, "slot {index} tail word");
            }
        }
    }
}
