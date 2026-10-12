//! Parameter value destruction — FUN_0803b5f0 @ 0x0803b5f0.
//! True extent: 204 bytes, [0x0803b5f0, 0x0803b6bc). Four plain outbound
//! BL instructions, zero predicated BL; inbound: one BL and one BLNE.
//! A descriptor destroy callback takes precedence. Otherwise resolve the type
//! from the descriptor or an indirect two-word value header, then reset scalar
//! defaults, detach borrowed values, or destroy owned buffers/pointer groups.
//! Type -4 recursively destroys the inner slot before freeing its container.
//! Deviations: omit the duplicate zero store; native descriptor/callback pointers
//! widen on hosts, while indirect value headers retain 32-bit firmware words.

use crate::drivers::ata_cmd::traced_free;
use crate::heap::flagged_pointer_group::flagged_pointer_group_destroy;
use crate::heap::owned_buffer::owned_buffer_destroy;

#[repr(C)]
pub struct ParameterValueCallbacks {
    pub reserved: [u32; 3],
    pub destroy: Option<unsafe extern "C" fn(*mut u32, *const ParameterValueDescriptor)>,
}

#[repr(C)]
pub struct ParameterValueDescriptor {
    pub kind: u8,
    pub reserved: [u8; 3],
    pub value_type: i32,
    pub metadata: [u32; 2],
    pub callbacks: *const ParameterValueCallbacks,
    pub default_value: u32,
}

/// `slot` must be writable. Without a descriptor its word must point to a
/// readable type word followed by a writable value word. Owned values must
/// satisfy the corresponding existing destructor's safety contract.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn parameter_value_destroy(
    mut slot: *mut u32,
    descriptor: *const ParameterValueDescriptor,
) {
    let value_type;
    if descriptor.is_null() {
        let header = slot.read() as usize as *mut u32;
        value_type = header.read() as i32;
        slot = header.add(1);
    } else {
        let callbacks = (*descriptor).callbacks;
        if !callbacks.is_null() {
            if let Some(destroy) = (*callbacks).destroy {
                destroy(slot, descriptor);
                return;
            }
        }
        value_type = if (*descriptor).kind == 5 { -1 } else { (*descriptor).value_type };
        if (*descriptor).kind != 5 && value_type == 1 {
            slot.write((*descriptor).default_value);
            return;
        }
    }
    if slot.read() == 0 { return; }
    match value_type {
        -4 => {
            parameter_value_destroy(slot, core::ptr::null());
            traced_free(slot.read() as usize as *mut u8);
        }
        1 => {
            slot.write(u32::MAX);
            return;
        }
        5 => {}
        6 => flagged_pointer_group_destroy(slot.read() as usize as *mut _),
        _ => owned_buffer_destroy(slot.read() as usize as *mut _),
    }
    slot.write(0);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::drivers::ata_cmd::{TracedFreeHooks, TRACED_FREE_HOOKS};
    use std::vec::Vec;
    static mut FREED: Vec<usize> = Vec::new();
    unsafe extern "C" fn free(block: *mut u8) {
        (*core::ptr::addr_of_mut!(FREED)).push(block as usize);
    }
    unsafe extern "C" fn override_destroy(slot: *mut u32, descriptor: *const ParameterValueDescriptor) {
        slot.write((*descriptor).default_value + 10);
    }
    fn descriptor(kind: u8, value_type: i32) -> ParameterValueDescriptor {
        ParameterValueDescriptor { kind, reserved: [0; 3], value_type, metadata: [0; 2],
            callbacks: core::ptr::null(), default_value: 42 }
    }
    #[test]
    fn scalar_default_null_borrowed_and_callback_precedence() {
        unsafe {
            let mut slot = 0;
            let mut desc = descriptor(0, 1);
            parameter_value_destroy(&mut slot, &desc);
            assert_eq!(slot, 42);
            desc.value_type = 5;
            slot = 0x1234;
            parameter_value_destroy(&mut slot, &desc);
            assert_eq!(slot, 0);
            desc.value_type = -4;
            parameter_value_destroy(&mut slot, &desc);
            assert_eq!(slot, 0);
            let callbacks = ParameterValueCallbacks { reserved: [0; 3], destroy: Some(override_destroy) };
            desc.callbacks = &callbacks;
            parameter_value_destroy(&mut slot, &desc);
            assert_eq!(slot, 52);
        }
    }
    #[test]
    fn indirect_scalar_and_recursive_container_release() {
        let _lock = crate::testing::TRACED_ALLOC_TEST_LOCK.lock().unwrap();
        let slab = crate::testing::try_map_u32_slab(
            crate::testing::hints::PARAMETER_VALUE_DESTROY, 4096,
        ).expect("32-bit header fixture");
        unsafe {
            let old = core::ptr::read(core::ptr::addr_of!(TRACED_FREE_HOOKS));
            TRACED_FREE_HOOKS = TracedFreeHooks { free, trace: None };
            (*core::ptr::addr_of_mut!(FREED)).clear();
            let header = slab.cast::<u32>();
            header.write(1);
            header.add(1).write(9);
            let mut slot = header as usize as u32;
            parameter_value_destroy(&mut slot, core::ptr::null());
            assert_eq!(slot, header as usize as u32);
            assert_eq!(header.add(1).read(), u32::MAX);
            header.add(1).write(0);
            parameter_value_destroy(&mut slot, core::ptr::null());
            assert_eq!(header.add(1).read(), 0);
            header.write(5);
            header.add(1).write(0x1234);
            parameter_value_destroy(&mut slot, &descriptor(0, -4));
            assert_eq!(header.add(1).read(), 0);
            assert_eq!(slot, 0);
            assert_eq!(&*core::ptr::addr_of!(FREED), &[header as usize]);
            // Kind 5 must ignore even a scalar type/default and destroy an owner.
            let owner = slab.add(64).cast::<crate::heap::owned_buffer::OwnedBuffer>();
            owner.write(crate::heap::owned_buffer::OwnedBuffer {
                length: 0, source: 0, data: core::ptr::null_mut(), context: 0,
            });
            slot = owner as usize as u32;
            parameter_value_destroy(&mut slot, &descriptor(5, 1));
            assert_eq!(slot, 0);
            assert_eq!(&*core::ptr::addr_of!(FREED), &[header as usize, owner as usize]);
            TRACED_FREE_HOOKS = old;
        }
    }
}
