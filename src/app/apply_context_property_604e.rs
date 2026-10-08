//! Apply the class-0x6000 property 0x604e to its context.
//!
//! Original FUN_08112fd8 @ 0x08112fd8: 64-byte true extent ending at
//! 0x08113018 (56 instruction bytes, then two literal words). Raw A32 scan
//! verifies two inbound plain BLs at 0x08116e04 and 0x08289b98, zero
//! predicated inbound BLs, zero outbound immediate BLs (plain or predicated),
//! one register BLX at 0x08112ff0, and one tail BX at 0x0811300c.
//! Store the raw property at +0x47c, refresh the child at +0x430 through
//! virtual slot +0x68, then reload the context vtable and notify slot +0x58
//! with tag 0x436e746c and event 0x63fd. Concrete virtual callee identities
//! remain unresolved; neither is replaced by a guessed address seam.
//!
//! Deliberate deviations: repr(C) pointers and vtable slots widen on hosts;
//! field order preserves the target layout. Rust expresses the tail dispatch
//! as a final void call; no return value is consumed by the verified callers.

#[repr(C)]
pub struct Property604eContextVtable {
    pub reserved: [usize; 0x58 / 4],
    pub notify: unsafe extern "C" fn(*mut Property604eContext, u32, u32),
}

#[repr(C)]
pub struct Property604eChildVtable {
    pub reserved: [usize; 0x68 / 4],
    pub refresh: unsafe extern "C" fn(*mut Property604eChild),
}

#[repr(C)]
pub struct Property604eChild {
    pub vtable: *const Property604eChildVtable,
}

#[repr(C)]
pub struct Property604eContext {
    pub vtable: *const Property604eContextVtable,
    pub reserved_004_42c: [u32; (0x430 - 4) / 4],
    pub child: *mut Property604eChild,
    pub reserved_434_478: [u32; (0x47c - 0x434) / 4],
    pub property_604e: u32,
}

/// # Safety
/// `context` must have the target layout (native repr(C) layout on hosts),
/// a valid child, and callable virtual slots +0x68 on the child and +0x58
/// on the context. Neither pointer is checked by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn apply_context_property_604e(context: *mut u8, value: u32) {
    let context = context.cast::<Property604eContext>();
    core::ptr::addr_of_mut!((*context).property_604e).write(value);
    let child = core::ptr::addr_of!((*context).child).read();
    let child_vtable = core::ptr::addr_of!((*child).vtable).read();
    ((*child_vtable).refresh)(child);
    // Refresh may replace the context's notification vtable.
    let context_vtable = core::ptr::addr_of!((*context).vtable).read();
    ((*context_vtable).notify)(context, 0x436e746c, 0x63fd);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Child {
        interface: Property604eChild,
        context: *mut Property604eContext,
        expected: u32,
        calls: u32,
    }

    unsafe extern "C" fn refresh(child: *mut Property604eChild) {
        let child = child.cast::<Child>();
        let context = (*child).context;
        assert_eq!((*context).property_604e, (*child).expected);
        (*child).calls += 1;
        (*context).property_604e ^= 0x80000000;
        (*context).vtable = &NOTIFY;
    }
    unsafe extern "C" fn notify(context: *mut Property604eContext, tag: u32, event: u32) {
        let child = (*context).child.cast::<Child>();
        assert_eq!((*child).calls, (*context).reserved_004_42c[0] + 1);
        assert_eq!((*context).property_604e, (*child).expected ^ 0x80000000);
        assert_eq!((tag, event), (0x436e746c, 0x63fd));
        (*context).reserved_004_42c[0] += 1;
    }
    unsafe extern "C" fn stale_notify(_: *mut Property604eContext, _: u32, _: u32) {
        panic!("notification used vtable cached before refresh");
    }
    static NOTIFY: Property604eContextVtable = Property604eContextVtable {
        reserved: [0; 0x58 / 4], notify,
    };

    #[test]
    fn stores_full_word_before_refresh_and_reloads_notification_after_each_call() {
        let child_vtable = Property604eChildVtable { reserved: [0; 0x68 / 4], refresh };
        let old_vtable = Property604eContextVtable { reserved: [0; 0x58 / 4], notify: stale_notify };
        let mut child = Child { interface: Property604eChild { vtable: &child_vtable },
            context: core::ptr::null_mut(), expected: 0, calls: 0 };
        let mut context = Property604eContext {
            vtable: &old_vtable, reserved_004_42c: [0x12345678; (0x430 - 4) / 4],
            child: &mut child.interface, reserved_434_478: [0x87654321; (0x47c - 0x434) / 4],
            property_604e: 99,
        };
        context.reserved_004_42c[0] = 0;
        child.context = &mut context;
        for value in [0, 0x3f, 0x80000000, u32::MAX, u32::MAX] {
            child.expected = value;
            context.vtable = &old_vtable;
            unsafe { apply_context_property_604e((&mut context as *mut Property604eContext).cast(), value); }
            assert_eq!(context.property_604e, value ^ 0x80000000);
            assert_eq!(context.reserved_004_42c[0], child.calls);
            assert!(context.reserved_004_42c[1..].iter().all(|&word| word == 0x12345678));
            assert_eq!(context.reserved_434_478, [0x87654321; (0x47c - 0x434) / 4]);
            assert_eq!(context.child, &mut child.interface as *mut _);
        }
    }
}
