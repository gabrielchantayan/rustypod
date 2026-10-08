//! Compare the interface query results used by the volume-limit unlock flow.
//!
//! Original FUN_08112e44 @ 0x08112e44: true extent 60 bytes, ending at
//! the next function's push at 0x08112e80. Raw A32 decoding verifies two
//! inbound plain BLs (0x08202f50, 0x08202fc8), zero predicated inbound BLs,
//! zero outbound immediate BLs (plain or predicated), and two register BLX
//! calls (0x08112e58, 0x08112e6c). Query virtual slot +0x88 on the interface
//! at context+0x88c, reload that interface and its vtable, query slot +0x60,
//! and return exactly one when the full-word results agree, otherwise zero.
//! The caller selects GotoScreen_VolumeLimitLock_Unlock; concrete virtual
//! callee identities remain unresolved and no address seams are introduced.
//!
//! Deliberate deviations: native repr(C) pointers and vtable slots widen on
//! hosts, preserving field order and target word indices, not host offsets.

#[repr(C)]
pub struct VolumeLimitQueryVtable {
    pub reserved_00_5c: [usize; 0x60 / 4],
    pub query_60: unsafe extern "C" fn(*mut VolumeLimitQueryInterface) -> u32,
    pub reserved_64_84: [usize; (0x88 - 0x64) / 4],
    pub query_88: unsafe extern "C" fn(*mut VolumeLimitQueryInterface) -> u32,
}

#[repr(C)]
pub struct VolumeLimitQueryInterface {
    pub vtable: *const VolumeLimitQueryVtable,
}

#[repr(C)]
pub struct VolumeLimitQueryContext {
    pub reserved_000_888: [u32; 0x88c / 4],
    pub interface: *mut VolumeLimitQueryInterface,
}

/// # Safety
/// The context, interface and both virtual slots must be valid. The first
/// callback may replace the interface or its vtable; the replacement must
/// provide a callable +0x60 slot. Neither pointer is checked by retailOS.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn volume_limit_query_results_equal(context: *mut VolumeLimitQueryContext) -> u32 {
    let interface = core::ptr::addr_of!((*context).interface).read();
    let vtable = core::ptr::addr_of!((*interface).vtable).read();
    let first = ((*vtable).query_88)(interface);
    let interface = core::ptr::addr_of!((*context).interface).read();
    let vtable = core::ptr::addr_of!((*interface).vtable).read();
    let second = ((*vtable).query_60)(interface);
    (second == first) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        interface: VolumeLimitQueryInterface,
        context: *mut VolumeLimitQueryContext,
        replacement: *mut VolumeLimitQueryInterface,
        replacement_vtable: *const VolumeLimitQueryVtable,
        first: u32,
        second: u32,
        calls: u32,
    }

    unsafe extern "C" fn first(interface: *mut VolumeLimitQueryInterface) -> u32 {
        let fixture = interface.cast::<Fixture>();
        assert_eq!((*fixture).calls, 0);
        (*fixture).calls = 1;
        if !(*fixture).replacement.is_null() {
            (*(*fixture).context).interface = (*fixture).replacement;
        }
        if !(*fixture).replacement_vtable.is_null() {
            (*fixture).interface.vtable = (*fixture).replacement_vtable;
        }
        (*fixture).first
    }
    unsafe extern "C" fn second(interface: *mut VolumeLimitQueryInterface) -> u32 {
        let fixture = interface.cast::<Fixture>();
        assert_eq!((*fixture).calls, 1);
        (*fixture).calls = 2;
        (*fixture).second
    }
    unsafe extern "C" fn stale(_: *mut VolumeLimitQueryInterface) -> u32 { 0x12345678 }
    fn vtable() -> VolumeLimitQueryVtable {
        VolumeLimitQueryVtable { reserved_00_5c: [0; 24], query_60: second,
            reserved_64_84: [0; 9], query_88: first }
    }
    fn fixture(vtable: *const VolumeLimitQueryVtable, first: u32, second: u32) -> Fixture {
        Fixture { interface: VolumeLimitQueryInterface { vtable }, context: core::ptr::null_mut(),
            replacement: core::ptr::null_mut(), replacement_vtable: core::ptr::null(),
            first, second, calls: 0 }
    }

    #[test]
    fn compares_full_words_and_normalizes_the_result() {
        let table = vtable();
        for a in [0, 1, 0x80000000, u32::MAX] {
            for b in [0, 1, 0x80000000, u32::MAX] {
                let mut object = fixture(&table, a, b);
                let mut context = VolumeLimitQueryContext { reserved_000_888: [99; 547], interface: &mut object.interface };
                assert_eq!(unsafe { volume_limit_query_results_equal(&mut context) }, (a == b) as u32);
                assert_eq!(object.calls, 2);
                assert_eq!(context.reserved_000_888, [99; 547]);
            }
        }
    }

    #[test]
    fn reloads_interface_and_vtable_after_first_query() {
        let table = vtable();
        let old = VolumeLimitQueryVtable { query_60: stale, ..vtable() };
        for replace_interface in [false, true] {
            let mut initial = fixture(&old, u32::MAX, u32::MAX);
            let mut replacement = fixture(&table, 0, u32::MAX);
            replacement.calls = 1;
            let mut context = VolumeLimitQueryContext { reserved_000_888: [0; 547], interface: &mut initial.interface };
            initial.context = &mut context;
            if replace_interface {
                initial.replacement = &mut replacement.interface;
            } else {
                initial.replacement_vtable = &table;
            }
            assert_eq!(unsafe { volume_limit_query_results_equal(&mut context) }, 1);
            assert_eq!(initial.calls, if replace_interface { 1 } else { 2 });
            assert_eq!(replacement.calls, if replace_interface { 2 } else { 1 });
        }
    }
}
