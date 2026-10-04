//! `context_operation_begin` — FUN_081f08f8 at 0x081f08f8, 100 bytes.
//! Raw extent [0x081f08f8,0x081f095c): 96 instruction bytes and a
//! four-byte literal; next real function starts at 0x081f095c.
//! One plain outbound BL, zero predicated BLs, one register BLX;
//! two plain inbound BLs (0x081f07f0 and 0x081f1044).
//!
//! Begin the embedded operation at +0x74, without waiting. With no
//! associated object (+0x48), use 10000 and two zero arguments. Otherwise
//! query vtable slot +0x3c for two arguments, initially zero, and use zero
//! for the default value. Ignore the operation's result. No target behavior
//! deviations: Ghidra's extra input arguments are not read by the raw code.
//! The verified unported operation-begin callee remains at 0x082234d4.
//! Host-only pointer fields and vtable entries widen to native pointer size.

#[repr(C)]
pub struct OperationContext {
    pub prefix: [u32; 18],
    pub associated: *mut u8,
    pub middle: [u32; 10],
    pub operation: [u32; 20],
}

type QueryArguments = unsafe extern "C" fn(*mut u8, *mut u32, *mut u32);
pub type OperationBegin = unsafe extern "C" fn(*mut u32, u32, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_begin(_: *mut u32, _: u32, _: u32, _: u32, _: u32) -> u32 {
    panic!("install context operation begin host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut CONTEXT_OPERATION_BEGIN: OperationBegin = missing_begin;

/// # Safety
/// Context and associated object must be valid firmware objects. Vtable slot
/// +0x3c must implement the two-output query contract; the embedded operation
/// must satisfy 0x082234d4's contract. Install host seams without races.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_operation_begin(context: *mut OperationContext) {
    let associated = (*context).associated;
    let mut first = 0;
    let mut second = 0;
    let default_value = if associated.is_null() {
        10000
    } else {
        let vtable = associated.cast::<*const usize>().read();
        let query: QueryArguments = core::mem::transmute(vtable.add(15).read());
        query(associated, &mut first, &mut second);
        0
    };
    #[cfg(target_os = "none")]
    let begin: OperationBegin = core::mem::transmute(0x0822_34d4usize);
    #[cfg(not(target_os = "none"))]
    let begin = core::ptr::addr_of!(CONTEXT_OPERATION_BEGIN).read_volatile();
    begin(core::ptr::addr_of_mut!((*context).operation).cast(), 0, default_value, first, second);
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct Object { vtable: *const usize, first: u32, second: u32, writes: u32, queries: u32 }
    unsafe extern "C" fn query(object: *mut u8, first: *mut u32, second: *mut u32) {
        let object = &mut *object.cast::<Object>();
        assert_eq!((*first, *second), (0, 0));
        object.queries += 1;
        if object.writes & 1 != 0 { *first = object.first; }
        if object.writes & 2 != 0 { *second = object.second; }
    }
    // Model the callee's started-state transition and already-started guard.
    unsafe extern "C" fn begin(operation: *mut u32, wait: u32, default_value: u32, first: u32, second: u32) -> u32 {
        assert_eq!(wait, 0);
        if operation.add(19).read() & 1 != 0 { return 1; }
        operation.add(17).write(default_value);
        operation.add(1).write(first);
        operation.add(2).write(second);
        operation.add(19).write(1);
        1
    }
    #[test]
    fn default_and_partial_virtual_outputs_start_once() {
        let _guard = LOCK.lock();
        unsafe { CONTEXT_OPERATION_BEGIN = begin; }
        let mut vtable = [0usize; 16];
        vtable[15] = query as *const () as usize;
        for writes in 0..4 {
            for (first, second) in [(0, 0), (u32::MAX, 0x80000000), (17, 29)] {
                let mut object = Object { vtable: vtable.as_ptr(), first, second, writes, queries: 0 };
                for attached in [false, true] {
                    let mut context = OperationContext {
                        prefix: [0xfeed; 18], associated: if attached { (&mut object as *mut Object).cast() } else { core::ptr::null_mut() },
                        middle: [0xbeef; 10], operation: [0; 20],
                    };
                    unsafe { context_operation_begin(&mut context); }
                    assert_eq!(context.operation[17], if attached { 0 } else { 10000 });
                    assert_eq!(context.operation[1], if attached && writes & 1 != 0 { first } else { 0 });
                    assert_eq!(context.operation[2], if attached && writes & 2 != 0 { second } else { 0 });
                    assert_eq!(context.operation[19], 1);
                    let started = context.operation;
                    unsafe { context_operation_begin(&mut context); }
                    assert_eq!(context.operation, started);
                    assert_eq!(context.prefix, [0xfeed; 18]);
                    assert_eq!(context.middle, [0xbeef; 10]);
                }
                assert_eq!(object.queries, 2);
            }
        }
    }
}
