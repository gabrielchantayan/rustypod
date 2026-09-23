//! `animation_property_pair_init` — original: `FUN_0814485c` @ `0x0814485c`.
//!
//! ## Binary evidence
//!
//! Raw `osos.dec` establishes the exact 108-byte extent
//! `0x0814485c..0x0814485c+0x6c`; `push {r4,lr}` at `0x081448c8` starts the
//! next real function. The body has eight plain unconditional `bl` calls and
//! no predicated `bl`: `operator_new` twice, `fixed_value_init` twice,
//! `operator_new`, `animation_init`, and `release_refcounted_value` twice.
//! Its final transfer is a `b` tail branch to `timing_wheel_insert_global`.
//!
//! ## Algorithm
//!
//! Allocates two Q16.16 fixed values from the supplied integer endpoints,
//! stores them at owner offsets `+0xc4` and `+0xc8`, allocates an animation
//! combining the owner's current value at `+0xc0` with those endpoints, stores
//! it at `+0xcc`, drops the two temporary ownership references, then links the
//! animation into the global timing wheel. There are no deliberate deviations.

use crate::app::animation::{animation_init, timing_wheel_insert_global, Animation};
use crate::app::fixed_value::{fixed_value_init, FixedValue};
use crate::app::refcounted_value::release_refcounted_value;
use crate::heap::veneers::operator_new;

/// Minimal target-width view of the owner fields touched by
/// [`animation_property_pair_init`].
#[repr(C)]
pub struct AnimationPropertyPairOwner {
    pub prefix: [u8; 0xc0],
    pub current_value: u32,
    pub from_value: u32,
    pub to_value: u32,
    pub animation: u32,
}

const _: [u8; 0xc0] = [0; core::mem::offset_of!(AnimationPropertyPairOwner, current_value)];
const _: [u8; 0xc4] = [0; core::mem::offset_of!(AnimationPropertyPairOwner, from_value)];
const _: [u8; 0xc8] = [0; core::mem::offset_of!(AnimationPropertyPairOwner, to_value)];
const _: [u8; 0xcc] = [0; core::mem::offset_of!(AnimationPropertyPairOwner, animation)];

/// Builds the two endpoint values and their animation for `owner`.
///
/// # Safety
/// `owner` must be a live, writable target-layout object through `+0xd0` and
/// its current-value word must point to a live [`FixedValue`]. Allocations and
/// scheduler state follow the same unguarded contracts as retailOS.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn animation_property_pair_init(
    owner: *mut AnimationPropertyPairOwner,
    _unused: u32,
    from: i32,
    to: i32,
) {
    let from_value = fixed_value_init(operator_new(core::mem::size_of::<FixedValue>()).cast(), from << 16);
    (*owner).from_value = from_value as usize as u32;

    let to_value = fixed_value_init(operator_new(core::mem::size_of::<FixedValue>()).cast(), to << 16);
    (*owner).to_value = to_value as usize as u32;

    let animation = animation_init(
        operator_new(core::mem::size_of::<Animation>()).cast(),
        ((*owner).current_value as usize) as *mut FixedValue,
        from_value,
        to_value,
    );
    (*owner).animation = animation as usize as u32;

    release_refcounted_value(from_value.cast());
    release_refcounted_value(to_value.cast());
    timing_wheel_insert_global(animation.cast());
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HEAP_OPS, HeapVeneerOps};
    use crate::heap::veneers::tests::mock_heap;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr::{addr_of_mut, null_mut};
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATIONS: [*mut u8; 3] = [null_mut(); 3];
    static mut ALLOCATION_INDEX: usize = 0;
    static mut REQUESTS: [(usize, usize); 3] = [(0, 0); 3];

    unsafe extern "C" fn allocate(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        let index = ALLOCATION_INDEX;
        ALLOCATION_INDEX += 1;
        REQUESTS[index] = (size, tag);
        ALLOCATIONS[index]
    }

    #[test]
    fn initializes_q16_endpoints_animation_and_owner_slots() {
        let _lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let _heap = mock_heap();
        let Some(storage) = try_map_u32_slab(hints::ANIMATION_PROPERTY_PAIR_INIT, 0x200) else {
            return;
        };
        unsafe {
            let owner = storage.cast::<AnimationPropertyPairOwner>();
            let current = storage.add(0xd0).cast::<FixedValue>();
            let from_value = storage.add(0xe8).cast::<FixedValue>();
            let to_value = storage.add(0x100).cast::<FixedValue>();
            let animation = storage.add(0x118).cast::<Animation>();
            core::ptr::write_bytes(owner.cast::<u8>(), 0, 0xd0);
            fixed_value_init(current, 0x0003_0000);
            (*owner).current_value = current as usize as u32;
            ALLOCATIONS = [from_value.cast(), to_value.cast(), animation.cast()];
            ALLOCATION_INDEX = 0;
            REQUESTS = [(0, 0); 3];
            let mut ops: HeapVeneerOps = core::ptr::read_volatile(addr_of_mut!(HEAP_OPS));
            ops.alloc = allocate;
            addr_of_mut!(HEAP_OPS).write(ops);

            animation_property_pair_init(owner, 0xfeed_face, -2, 255);

            assert_eq!(REQUESTS, [(0x18, 2), (0x18, 2), (0x24, 2)]);
            assert_eq!((*from_value).value_q16, -2 << 16);
            assert_eq!((*to_value).value_q16, 255 << 16);
            assert_eq!((*owner).from_value, from_value as usize as u32);
            assert_eq!((*owner).to_value, to_value as usize as u32);
            assert_eq!((*owner).animation, animation as usize as u32);
            assert_eq!((*animation).from_value, from_value as usize as u32);
            assert_eq!((*animation).to_value, to_value as usize as u32);
            assert_eq!((*animation).current_value, current as usize as u32);
        }
    }
}
