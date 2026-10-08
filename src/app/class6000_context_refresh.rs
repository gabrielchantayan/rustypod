//! Refresh a context from the class-0x6000 store.
//! Original FUN_08116dd8 @ 0x08116dd8; true extent 92 bytes through
//! 0x08116e30, next function at 0x08116e34. Raw whole-image A32 scan:
//! two incoming plain BLs (0x08112f88, 0x08115d28), seven outgoing
//! plain BLs, zero predicated BLs, and tail B to 0x081114ec.
//!
//! If the singleton is absent, return without accessing the context.
//! Otherwise refresh the store's cached properties, apply raw property
//! 0x604e, refresh the context's RTC object, store the 0x60ac predicate
//! byte at +0x460, then apply signed property 0x6045 via the stock helper.
//! The final helper scales by three after adding two and republishes the
//! context value; it performs a fresh singleton lookup. Preserve that
//! helper rather than folding its lookup into the first one.
//!
//! Deviations: native-width host pointer at fixed +0x88c offset (unaligned
//! host access), and an injectable operation table for host execution.
//! No target deviations.
//! Three unported helpers remain calls into verified stock code, not ports.

use super::class_8900::Class6000;

type Lookup = unsafe extern "C" fn() -> *mut Class6000;
type RefreshStore = unsafe extern "C" fn(*mut Class6000);
type ReadProperty = unsafe extern "C" fn(*mut Class6000) -> u32;
type ApplyProperty = unsafe extern "C" fn(*mut u8, u32);
type RefreshRtc = unsafe extern "C" fn(*mut u8) -> u32;
type ReadPredicate = unsafe extern "C" fn(*mut Class6000) -> bool;
type ReadSigned = unsafe extern "C" fn(*mut Class6000) -> i32;
type ApplySigned = unsafe extern "C" fn(*mut u8, i32);

#[derive(Clone, Copy)]
pub struct ContextRefreshOps {
    pub lookup: Lookup,
    pub refresh_store: RefreshStore,
    pub read_604e: ReadProperty,
    pub apply_604e: ApplyProperty,
    pub refresh_rtc: RefreshRtc,
    pub read_60ac: ReadPredicate,
    pub read_6045: ReadSigned,
    pub apply_6045: ApplySigned,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_lookup() -> *mut Class6000 { panic!("install context refresh operations") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_: *mut Class6000) { panic!("install store refresh") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read(_: *mut Class6000) -> u32 { panic!("install property 604e reader") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_signed(_: *mut u8, _: i32) { panic!("install property 6045 setter") }

unsafe extern "C" fn read_predicate(store: *mut Class6000) -> bool {
    super::class6000_property_60ac_is_602e::class6000_property_60ac_is_602e(store.cast())
}

#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_REFRESH_OPS: ContextRefreshOps = ContextRefreshOps {
    lookup: missing_lookup, refresh_store: missing_refresh,
    read_604e: missing_read, apply_604e: super::apply_context_property_604e::apply_context_property_604e,
    refresh_rtc: super::rtc_binding_refresh::rtc_binding_refresh,
    read_60ac: read_predicate,
    read_6045: super::class_6000_property_6045_i8::class6000_property_6045_i8,
    apply_6045: missing_signed,
};

#[inline(always)]
unsafe fn refresh_with(context: *mut u8, ops: &ContextRefreshOps) {
    let store = (ops.lookup)();
    if store.is_null() { return; }
    (ops.refresh_store)(store);
    let property = (ops.read_604e)(store);
    (ops.apply_604e)(context, property);
    #[cfg(target_os = "none")]
    let rtc = context.add(0x88c).cast::<*mut u8>().read();
    #[cfg(not(target_os = "none"))]
    let rtc = context.add(0x88c).cast::<*mut u8>().read_unaligned();
    (ops.refresh_rtc)(rtc);
    let predicate = (ops.read_60ac)(store);
    context.add(0x460).write(predicate as u8);
    let signed = (ops.read_6045)(store);
    (ops.apply_6045)(context, signed);
}

#[cfg(target_os = "none")]
unsafe extern "C" fn lookup_store() -> *mut Class6000 {
    super::registry::instance_of_class_6000().cast()
}

/// # Safety
/// With a non-null singleton, context must have writable +0x460 storage
/// and a valid RTC pointer at +0x88c. All stock dependencies must be valid.
/// Host operation installation must be serialized against callers.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn class6000_context_refresh(context: *mut u8) {
    #[cfg(target_os = "none")]
    let ops = ContextRefreshOps {
        lookup: lookup_store,
        refresh_store: core::mem::transmute(0x0817_2c6cusize),
        read_604e: core::mem::transmute(0x0817_2700usize),
        apply_604e: super::apply_context_property_604e::apply_context_property_604e,
        refresh_rtc: super::rtc_binding_refresh::rtc_binding_refresh,
        read_60ac: read_predicate,
        read_6045: super::class_6000_property_6045_i8::class6000_property_6045_i8,
        apply_6045: core::mem::transmute(0x0811_14ecusize),
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(CONTEXT_REFRESH_OPS).read();
    refresh_with(context, &ops);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::class_8900::Class6000VTable;
    use super::super::resource_chain::ResourceKind;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut STORE: *mut Class6000 = core::ptr::null_mut();
    static mut PROPERTY: u32 = 0;
    static mut SIGNED: u32 = 0;
    static mut RTC: *mut u8 = core::ptr::null_mut();
    unsafe extern "C" fn lookup() -> *mut Class6000 { STORE }
    unsafe extern "C" fn refresh(_: *mut Class6000) { PROPERTY ^= 1; }
    unsafe extern "C" fn read(_: *mut Class6000) -> u32 { PROPERTY }
    unsafe extern "C" fn apply(context: *mut u8, value: u32) {
        context.add(0x47c).cast::<u32>().write(value);
        context.add(0x88c).cast::<*mut u8>().write_unaligned(RTC);
    }
    unsafe extern "C" fn rtc(object: *mut u8) -> u32 {
        let generation = object.cast::<u32>();
        generation.write(generation.read().wrapping_add(1));
        0
    }
    unsafe extern "C" fn predicate(_: *mut Class6000, _: u32, _: u32) -> u32 {
        if PROPERTY & 1 != 0 { 0x602e } else { 0 }
    }
    unsafe extern "C" fn signed(_: *mut Class6000, _: u32, _: u32, _: ResourceKind) -> *mut u32 {
        SIGNED as usize as *mut u32
    }
    unsafe extern "C" fn finish(context: *mut u8, value: i32) {
        // The stock setter is responsible for scaling, not this port.
        assert_eq!(context.add(0x460).read(), (PROPERTY & 1) as u8);
        assert_eq!(RTC.cast::<u32>().read(), 0);
        context.add(0x6fc).cast::<u32>().write((value as u32).wrapping_add(2).wrapping_mul(3));
    }
    fn ops() -> ContextRefreshOps {
        ContextRefreshOps { lookup, refresh_store: refresh, read_604e: read,
            apply_604e: apply, refresh_rtc: rtc, read_60ac: read_predicate,
            read_6045: super::super::class_6000_property_6045_i8::class6000_property_6045_i8,
            apply_6045: finish }
    }
    #[repr(align(8))]
    struct Context([u8; 0x898]);

    #[test]
    fn absent_store_preserves_context_and_cached_state() {
        let _lock = LOCK.lock();
        let mut context = Context([0xa5; 0x898]);
        unsafe {
            STORE = core::ptr::null_mut();
            PROPERTY = 0xdead_beef;
            refresh_with(context.0.as_mut_ptr(), &ops());
            refresh_with(core::ptr::null_mut(), &ops());
            let property = PROPERTY;
            assert_eq!(property, 0xdead_beef);
        }
        assert_eq!(context.0, [0xa5; 0x898]);
    }

    #[test]
    fn refreshed_properties_replace_state_and_use_rtc_replaced_by_setter() {
        let _lock = LOCK.lock();
        let vtable = Class6000VTable { slots_below: [None; 55], read: predicate, read_typed: signed };
        let mut store = Class6000 { vtable: &vtable };
        let mut context = Context([0xa5; 0x898]);
        let mut old_rtc = 12u32;
        let mut new_rtc = u32::MAX;
        unsafe {
            STORE = &mut store;
            RTC = (&mut new_rtc as *mut u32).cast();
            for (property, raw, expected) in [(0u32, 0x80u32, (-126i32 * 3) as u32),
                (u32::MAX, 0xffff_ff7f, 129 * 3), (0, 0xff, 3), (1, 0, 6)] {
                PROPERTY = property;
                SIGNED = raw;
                new_rtc = u32::MAX;
                context.0.as_mut_ptr().add(0x88c).cast::<*mut u8>().write_unaligned((&mut old_rtc as *mut u32).cast());
                refresh_with(context.0.as_mut_ptr(), &ops());
                assert_eq!(context.0.as_ptr().add(0x47c).cast::<u32>().read(), property ^ 1);
                assert_eq!(context.0[0x460], ((property ^ 1) & 1) as u8);
                assert_eq!(context.0.as_ptr().add(0x6fc).cast::<u32>().read(), expected);
                assert_eq!(old_rtc, 12);
                assert_eq!(new_rtc, 0);
                assert_eq!(&context.0[0x45c..0x460], &[0xa5; 4]);
                assert_eq!(&context.0[0x461..0x465], &[0xa5; 4]);
            }
            STORE = core::ptr::null_mut();
            RTC = core::ptr::null_mut();
        }
    }
}
