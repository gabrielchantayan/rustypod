//! Advance the Cover Flow model and publish its changed properties.
//!
//! Original `FUN_0816cfb8` at 0x0816cfb8, true extent 120 bytes
//! [0x0816cfb8,0x0816d030): 100 code bytes and five literal words. The next
//! function begins with `cmp r1,#0`. Raw A32 verifies two outgoing plain BLs,
//! zero predicated BLs, two virtual BLX calls and a final virtual BX. Inbound:
//! one plain BL at 0x0816d12c and one BLNE at 0x0816d69c.
//! Forward the signed step to the model at owner +0xb0 (0x081429e4), obtain
//! the existing class-0x7a00 singleton, then notify (VMax,0x7a0b),
//! (Str ,0x7a09), (Str ,0x7a0a) through slot +0x58, reloading its vtable
//! before every dispatch. Callers identify next/previous/wheel navigation.
//! Deliberate deviations: host pointers widen via repr(C); the unported
//! model update uses a typed retail-address seam. The final tail dispatch
//! is expressed as a final Rust call; no new NULL or step validation.

use crate::app::singletons::singleton_class_7a00_instance;

#[repr(C)]
pub struct CoverFlowOwner {
    pub reserved: [u32; 44],
    pub model: *mut u8,
}

#[repr(C)]
pub struct CoverFlowNotificationVtable {
    pub reserved: [usize; 22],
    pub notify: unsafe extern "C" fn(*mut CoverFlowNotifications, u32, u32),
}

#[repr(C)]
pub struct CoverFlowNotifications {
    pub vtable: *const CoverFlowNotificationVtable,
}

type ModelStep = unsafe extern "C" fn(*mut u8, i32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_model_step(model: *mut u8, step: i32) {
    let update: ModelStep = core::mem::transmute(0x0814_29e4usize);
    update(model, step);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_model_step(_: *mut u8, _: i32) {
    panic!("install Cover Flow model-step seam for 0x081429e4")
}

#[cfg(target_os = "none")]
pub static mut COVER_FLOW_MODEL_STEP: ModelStep = retail_model_step;
#[cfg(not(target_os = "none"))]
pub static mut COVER_FLOW_MODEL_STEP: ModelStep = missing_model_step;

/// # Safety
/// Owner +0xb0 must hold a valid model for the retail update. The class-0x7a00
/// singleton must be non-NULL with a valid callable vtable slot +0x58, including
/// after each callback. No NULL checks exist in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cover_flow_step(owner: *mut CoverFlowOwner, step: i32) {
    core::ptr::read_volatile(core::ptr::addr_of!(COVER_FLOW_MODEL_STEP))((*owner).model, step);
    let notifications = singleton_class_7a00_instance().cast::<CoverFlowNotifications>();
    for (kind, property) in [(0x564d_6178, 0x7a0b), (0x5374_7220, 0x7a09), (0x5374_7220, 0x7a0a)] {
        let vtable = core::ptr::read_volatile(core::ptr::addr_of!((*notifications).vtable));
        let notify = core::ptr::read_volatile(core::ptr::addr_of!((*vtable).notify));
        notify(notifications, kind, property);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::singletons::{SINGLETON_LOCK, SINGLETON_CLASS_7A00_INSTANCE};

    #[repr(C)]
    struct Fixture {
        notifications: CoverFlowNotifications,
        step: i32,
        stage: u32,
        properties: [u32; 3],
    }

    unsafe extern "C" fn update(model: *mut u8, step: i32) {
        let fixture = &mut *model.cast::<Fixture>();
        assert_eq!(fixture.stage, 0);
        fixture.step = step;
        fixture.stage = 1;
        // The getter must run after the model update, not before it.
        SINGLETON_CLASS_7A00_INSTANCE = model;
    }

    unsafe extern "C" fn first(receiver: *mut CoverFlowNotifications, kind: u32, property: u32) {
        let fixture = &mut *receiver.cast::<Fixture>();
        assert_eq!((fixture.stage, kind, property), (1, 0x564d_6178, 0x7a0b));
        fixture.properties[0] = property;
        fixture.stage = 2;
        fixture.notifications.vtable = &SECOND;
    }

    unsafe extern "C" fn second(receiver: *mut CoverFlowNotifications, kind: u32, property: u32) {
        let fixture = &mut *receiver.cast::<Fixture>();
        assert_eq!((fixture.stage, kind, property), (2, 0x5374_7220, 0x7a09));
        fixture.properties[1] = property;
        fixture.stage = 3;
        fixture.notifications.vtable = &THIRD;
    }

    unsafe extern "C" fn third(receiver: *mut CoverFlowNotifications, kind: u32, property: u32) {
        let fixture = &mut *receiver.cast::<Fixture>();
        assert_eq!((fixture.stage, kind, property), (3, 0x5374_7220, 0x7a0a));
        fixture.properties[2] = property;
        fixture.stage = 4;
    }

    static FIRST: CoverFlowNotificationVtable = CoverFlowNotificationVtable { reserved: [0; 22], notify: first };
    static SECOND: CoverFlowNotificationVtable = CoverFlowNotificationVtable { reserved: [0; 22], notify: second };
    static THIRD: CoverFlowNotificationVtable = CoverFlowNotificationVtable { reserved: [0; 22], notify: third };

    #[test]
    fn signed_steps_publish_after_update_and_follow_vtable_replacement() {
        let _guard = SINGLETON_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        unsafe {
            let old_update = COVER_FLOW_MODEL_STEP;
            let old_instance = SINGLETON_CLASS_7A00_INSTANCE;
            COVER_FLOW_MODEL_STEP = update;
            for step in [i32::MIN, -1, 0, 1, 2, i32::MAX] {
                let mut fixture = Fixture { notifications: CoverFlowNotifications { vtable: &FIRST }, step: 99, stage: 0, properties: [0; 3] };
                let mut owner = CoverFlowOwner { reserved: [0xa5a5_a5a5; 44], model: (&mut fixture as *mut Fixture).cast() };
                SINGLETON_CLASS_7A00_INSTANCE = core::ptr::null_mut();
                cover_flow_step(&mut owner, step);
                assert_eq!(fixture.step, step);
                assert_eq!(fixture.stage, 4);
                assert_eq!(fixture.properties, [0x7a0b, 0x7a09, 0x7a0a]);
                assert_eq!(owner.reserved, [0xa5a5_a5a5; 44]);
            }
            COVER_FLOW_MODEL_STEP = old_update;
            SINGLETON_CLASS_7A00_INSTANCE = old_instance;
        }
    }
}
