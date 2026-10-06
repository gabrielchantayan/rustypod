//! `class6000_write_ui32_property_6056` — `FUN_08172004` @ `0x08172004`.
//! True extent: 152 bytes (132 instruction bytes, 20 literal bytes); next
//! real function: `0x0817209c`. Raw binary scan: 2 plain BL callers
//! (`0x081116f8`, `0x081ed008`), 0 predicated BL callers. Body: 0 BL,
//! 4 unconditional register BLX calls.
//!
//! Write `(key 0x6056, class 0x6000, &value, "Ui32")` through slot +0xd8,
//! then notify slot +0x58 with ("Cntl", 0x6056), ("Cntl", 0x63f9),
//! and ("Str ", 0x60ed), reloading the vtable before every call. The
//! property's broader identity is not assumed. Ghidra's sixth write argument
//! is the saved r0 above the one stack argument, not an actual argument.
//!
//! Deliberate deviation: native-pointer repr(C) fixtures widen vtable slots
//! on hosts; target offsets are asserted. No behavioral deviations.

#[repr(C)]
pub struct Property6056Store {
    pub vtable: *const Property6056VTable,
}

#[repr(C)]
pub struct Property6056VTable {
    pub slots_00_54: [usize; 22],
    pub notify: unsafe extern "C" fn(*mut Property6056Store, u32, u32),
    pub slots_5c_d4: [usize; 31],
    pub write_typed: unsafe extern "C" fn(*mut Property6056Store, u32, u32, *mut u32, u32),
}

#[cfg(target_pointer_width = "32")]
const _: [(); 0x58] = [(); core::mem::offset_of!(Property6056VTable, notify)];
#[cfg(target_pointer_width = "32")]
const _: [(); 0xd8] = [(); core::mem::offset_of!(Property6056VTable, write_typed)];

/// # Safety
/// `store` must have a live vtable with callable slots +0xd8 and +0x58.
/// The write callback may use the value pointer only during its call. Each
/// callback must leave a valid store/vtable for the following notification.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class6000_write_ui32_property_6056(store: *mut Property6056Store, mut value: u32) {
    let vtable = core::ptr::addr_of!((*store).vtable).read_volatile();
    ((*vtable).write_typed)(store, 0x6056, 0x6000, &mut value, 0x5569_3332);
    let vtable = core::ptr::addr_of!((*store).vtable).read_volatile();
    ((*vtable).notify)(store, 0x436e_746c, 0x6056);
    let vtable = core::ptr::addr_of!((*store).vtable).read_volatile();
    ((*vtable).notify)(store, 0x436e_746c, 0x63f9);
    let vtable = core::ptr::addr_of!((*store).vtable).read_volatile();
    ((*vtable).notify)(store, 0x5374_7220, 0x60ed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        store: Property6056Store,
        value: u32,
        stage: u32,
    }
    unsafe extern "C" fn write(store: *mut Property6056Store, key: u32, class: u32, value: *mut u32, kind: u32) {
        let fixture = &mut *store.cast::<Fixture>();
        assert_eq!((key, class, kind), (0x6056, 0x6000, 0x5569_3332));
        assert_eq!(*value, fixture.value);
        *value = 0xdead_beef;
        fixture.stage = 1;
        fixture.store.vtable = &FIRST;
    }
    unsafe extern "C" fn first(store: *mut Property6056Store, kind: u32, event: u32) {
        let fixture = &mut *store.cast::<Fixture>();
        assert_eq!((fixture.stage, kind, event), (1, 0x436e_746c, 0x6056));
        fixture.stage = 2;
        fixture.store.vtable = &SECOND;
    }
    unsafe extern "C" fn second(store: *mut Property6056Store, kind: u32, event: u32) {
        let fixture = &mut *store.cast::<Fixture>();
        assert_eq!((fixture.stage, kind, event), (2, 0x436e_746c, 0x63f9));
        fixture.stage = 3;
        fixture.store.vtable = &LAST;
    }
    unsafe extern "C" fn last(store: *mut Property6056Store, kind: u32, event: u32) {
        let fixture = &mut *store.cast::<Fixture>();
        assert_eq!((fixture.stage, kind, event), (3, 0x5374_7220, 0x60ed));
        fixture.stage = 4;
    }
    const fn table(notify: unsafe extern "C" fn(*mut Property6056Store, u32, u32)) -> Property6056VTable {
        Property6056VTable { slots_00_54: [0; 22], notify, slots_5c_d4: [0; 31], write_typed: write }
    }
    static INITIAL: Property6056VTable = table(last);
    static FIRST: Property6056VTable = table(first);
    static SECOND: Property6056VTable = table(second);
    static LAST: Property6056VTable = table(last);

    #[test]
    fn preserves_all_value_bits_and_observes_callback_vtable_replacements() {
        for value in [0, 1, 100, 101, 0x8000_0000, u32::MAX] {
            let mut fixture = Fixture { store: Property6056Store { vtable: &INITIAL }, value, stage: 0 };
            unsafe { class6000_write_ui32_property_6056(&mut fixture.store, value); }
            assert_eq!(fixture.stage, 4);
            assert_eq!(fixture.value, value);
        }
    }
}
