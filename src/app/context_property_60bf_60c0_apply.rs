//! `context_property_60bf_60c0_apply` — FUN_0816a9d8 @ 0x0816a9d8.
//! True extent [0x0816a9d8,0x0816aa50): 120 bytes, including two literals.
//! Raw A32 scan: two inbound plain BLs (0x0816a888, 0x0816a994), no
//! predicated inbound BLs; one outbound plain BL, no predicated BLs, three BLX.
//! Resolve class 0x6000; if present, query context member +0xe8's interface
//! at +0x38 through virtual +0x10. Reload the member and send its +0x44 word,
//! the query result, and selector 0x60c0 for zero direction or 0x60bf otherwise
//! through store virtual +0xd4. Then notify the context through virtual +0xd4.
//! Return 1 even when the store is absent. The next function starts at 0x0816aa50.
//! Deliberate deviations: repr(C) pointers and vtable words widen on hosts;
//! host singleton resolution is injectable. No guessed virtual method identity.

#[repr(C)]
pub struct PropertyContext {
    pub vtable: *const ContextVtable,
    pub reserved: [u32; 57],
    pub member: *mut PropertyMember,
}
#[repr(C)]
pub struct PropertyMember {
    pub reserved: [u32; 14],
    pub interface: *mut QueryInterface,
    pub middle: [u32; 2],
    pub value: u32,
}
#[repr(C)]
pub struct QueryInterface { pub vtable: *const QueryVtable }
#[repr(C)]
pub struct QueryVtable {
    pub reserved: [usize; 4],
    pub query: unsafe extern "C" fn(*mut QueryInterface) -> u32,
}
#[repr(C)]
pub struct PropertyStore { pub vtable: *const StoreVtable }
#[repr(C)]
pub struct StoreVtable {
    pub reserved: [usize; 53],
    pub apply: unsafe extern "C" fn(*mut PropertyStore, u32, u32, u32),
}
#[repr(C)]
pub struct ContextVtable {
    pub reserved: [usize; 53],
    pub notify: unsafe extern "C" fn(*mut PropertyContext),
}

#[cfg(not(target_os = "none"))]
pub static mut PROPERTY_STORE_INSTANCE: Option<unsafe extern "C" fn() -> *mut PropertyStore> = None;

/// # Safety
/// Present stores, context members, and all dispatched vtable slots must be
/// valid for the documented ABI. Callbacks may replace the context member.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn context_property_60bf_60c0_apply(context: *mut PropertyContext, direction: u32) -> u32 {
    #[cfg(target_os = "none")]
    let store = crate::app::registry::instance_of_class_6000().cast::<PropertyStore>();
    #[cfg(not(target_os = "none"))]
    let store = (core::ptr::addr_of!(PROPERTY_STORE_INSTANCE).read().expect("install property store resolver"))();
    if !store.is_null() {
        let interface = (*(*context).member).interface;
        let result = ((*(*interface).vtable).query)(interface);
        let apply = (*(*store).vtable).apply;
        let member = core::ptr::addr_of!((*context).member).read();
        apply(store, (*member).value, result, if direction == 0 { 0x60c0 } else { 0x60bf });
        ((*(*context).vtable).notify)(context);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut STORE: *mut PropertyStore = ptr::null_mut();
    static mut CONTEXT: *mut PropertyContext = ptr::null_mut();
    static mut REPLACEMENT: *mut PropertyMember = ptr::null_mut();
    static mut EVENTS: [u32; 5] = [0; 5];
    unsafe extern "C" fn instance() -> *mut PropertyStore { STORE }
    unsafe extern "C" fn query(_: *mut QueryInterface) -> u32 {
        EVENTS[0] = 1;
        (*CONTEXT).member = REPLACEMENT;
        u32::MAX
    }
    unsafe extern "C" fn apply(_: *mut PropertyStore, value: u32, result: u32, selector: u32) {
        assert_eq!(EVENTS[0], 1);
        EVENTS = [2, value, result, selector, 0];
    }
    unsafe extern "C" fn notify(_: *mut PropertyContext) {
        assert_eq!(EVENTS[0], 2);
        EVENTS[4] = 3;
    }
    #[test]
    fn missing_store_does_not_dereference_context() {
        let _guard = LOCK.lock();
        unsafe {
            STORE = ptr::null_mut();
            PROPERTY_STORE_INSTANCE = Some(instance);
            assert_eq!(context_property_60bf_60c0_apply(ptr::null_mut(), u32::MAX), 1);
            PROPERTY_STORE_INSTANCE = None;
        }
    }
    #[test]
    fn reloads_member_after_query_and_notifies_after_property_update() {
        let _guard = LOCK.lock();
        let qv = QueryVtable { reserved: [0; 4], query };
        let sv = StoreVtable { reserved: [0; 53], apply };
        let cv = ContextVtable { reserved: [0; 53], notify };
        let mut interface = QueryInterface { vtable: &qv };
        let mut original = PropertyMember { reserved: [0; 14], interface: &mut interface, middle: [0; 2], value: 7 };
        let mut replacement = PropertyMember { reserved: [0; 14], interface: ptr::null_mut(), middle: [0; 2], value: 0x80000000 };
        let mut context = PropertyContext { vtable: &cv, reserved: [0xaaaa; 57], member: &mut original };
        let mut store = PropertyStore { vtable: &sv };
        unsafe {
            STORE = &mut store; CONTEXT = &mut context; REPLACEMENT = &mut replacement;
            PROPERTY_STORE_INSTANCE = Some(instance);
            for direction in [0, 1, 0x80000000, u32::MAX] {
                context.member = &mut original;
                EVENTS = [0; 5];
                assert_eq!(context_property_60bf_60c0_apply(&mut context, direction), 1);
                let events = core::ptr::addr_of!(EVENTS).read();
                assert_eq!(events, [2, 0x80000000, u32::MAX, if direction == 0 { 0x60c0 } else { 0x60bf }, 3]);
                assert_eq!(context.member, &mut replacement as *mut _);
                assert_eq!(context.reserved, [0xaaaa; 57]);
            }
            STORE = ptr::null_mut(); CONTEXT = ptr::null_mut(); REPLACEMENT = ptr::null_mut();
            PROPERTY_STORE_INSTANCE = None;
        }
    }
}
