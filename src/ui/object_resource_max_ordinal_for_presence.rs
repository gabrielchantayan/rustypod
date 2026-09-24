//! Selects the greatest ordinal among UI resources with the requested presence.
use super::object_resource_count::object_resource_count;

const BACKEND_OFFSET: usize = 0x30;
const RESOURCE_VECTOR_OFFSET: usize = 0xf64;
const RESOURCE_ORDINAL_OFFSET: usize = 0x210;
const RESOURCE_VALUE_OFFSET: usize = 0x218;

/// object_resource_max_ordinal_for_presence — original: `FUN_0811457c` @
/// `0x0811457c` (112 bytes).
///
/// Raw ARM decodes from `push {r4-r10,lr}` at `0x0811457c` through
/// `pop {r4-r10,pc}` at `0x081145ec`; `ldr r0,[r0,#0x430]` at `0x081145f0`
/// begins the next real function. It has three plain direct `bl` instructions
/// (to `0x0805417c`, `0x08052314`, and `0x08054afc`) and no predicated direct
/// `bl` instructions.
///
/// Loads the context's backend, scans its resource-pointer vector, and returns
/// one more than the largest `+0x210` ordinal whose `+0x218` u64 is zero or
/// nonzero exactly as requested. Rust directly loads the two unported resource
/// entry fields instead of inventing names or seams for their callees; it
/// otherwise preserves the stock signed loop bound, raw selector comparison,
/// and lack of null, alignment, or bounds checks.
///
/// # Safety
///
/// `context`, its backend pointer at `+0x30`, the backend resource vector, and
/// every resource selected by the signed resource count must be readable with
/// the target's aligned layout.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_max_ordinal_for_presence(
    context: *const u8,
    has_value: u32,
) -> u32 {
    let backend = (context.add(BACKEND_OFFSET) as *const u32).read() as usize as *const u8;
    let resource_count = object_resource_count(backend) as i32;
    let resources = (backend.add(RESOURCE_VECTOR_OFFSET) as *const u32).read() as usize as *const u32;
    let mut greatest_ordinal = 0;
    let mut index = 0;

    while index < resource_count {
        let resource = resources.add(index as usize).read() as usize as *const u8;
        let has_resource_value = (resource.add(RESOURCE_VALUE_OFFSET) as *const u64).read() != 0;
        let ordinal = (resource.add(RESOURCE_ORDINAL_OFFSET) as *const i32).read();
        if has_value == has_resource_value as u32 && greatest_ordinal < ordinal {
            greatest_ordinal = ordinal;
        }
        index += 1;
    }

    (greatest_ordinal + 1) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    const RESOURCE_SIZE: usize = RESOURCE_VALUE_OFFSET + 8;

    unsafe fn write_word(base: *mut u8, offset: usize, value: u32) {
        (base.add(offset) as *mut u32).write(value);
    }

    unsafe fn set_resource(resource: *mut u8, ordinal: i32, value: u64) {
        write_word(resource, RESOURCE_ORDINAL_OFFSET, ordinal as u32);
        (resource.add(RESOURCE_VALUE_OFFSET) as *mut u64).write(value);
    }

    unsafe fn fixture(hint: usize) -> Option<(*mut u8, *mut u8, *mut u32, *mut u8, *mut u8, *mut u8)> {
        let slab = crate::testing::try_map_u32_slab(hint, 0x4000)?;
        let context = slab;
        let backend = slab.add(0x100);
        let resources = slab.add(0x1200).cast::<u32>();
        let first = slab.add(0x2000);
        let second = first.add(RESOURCE_SIZE);
        let third = second.add(RESOURCE_SIZE);
        ptr::write_bytes(slab, 0, 0x4000);
        context.add(BACKEND_OFFSET).cast::<u32>().write(backend as usize as u32);
        backend.write(1);
        write_word(backend, 0xf68, 3);
        write_word(backend, RESOURCE_VECTOR_OFFSET, resources as usize as u32);
        resources.write(first as usize as u32);
        resources.add(1).write(second as usize as u32);
        resources.add(2).write(third as usize as u32);
        Some((context, backend, resources, first, second, third))
    }

    #[test]
    fn chooses_the_largest_ordinal_with_a_nonzero_value() {
        let Some((context, _, _, first, second, third)) = (unsafe {
            fixture(crate::testing::hints::OBJECT_RESOURCE_MAX_ORDINAL_FOR_PRESENCE)
        }) else {
            return;
        };
        unsafe {
            set_resource(first, 99, 0);
            set_resource(second, 3, 1);
            set_resource(third, 7, 0x0100_0000_0000_0000);
        }

        assert_eq!(unsafe { object_resource_max_ordinal_for_presence(context, 1) }, 8);
    }

    #[test]
    fn chooses_zero_value_resources_and_requires_the_raw_boolean_selector() {
        let Some((context, _, _, first, second, third)) = (unsafe {
            fixture(crate::testing::hints::OBJECT_RESOURCE_MAX_ORDINAL_FOR_PRESENCE_RAW_SELECTOR)
        }) else {
            return;
        };
        unsafe {
            set_resource(first, 2, 0);
            set_resource(second, 8, 1);
            set_resource(third, 5, 0);
        }

        assert_eq!(unsafe { object_resource_max_ordinal_for_presence(context, 0) }, 6);
        assert_eq!(unsafe { object_resource_max_ordinal_for_presence(context, 2) }, 1);
    }
}
