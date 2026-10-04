//! Complete a record selection — `FUN_08202000`, load address 0x08202000.
//! True extent 144 bytes, ending at the next push at 0x08202090. Raw words
//! verify 15 outbound plain BLs, zero predicated BLs, one tail B; two inbound
//! plain BLs (0x08201f10, 0x082022a0), zero predicated inbound BLs.
//!
//! Begin a pending UI operation, capture its current context, update the
//! selected record's status and slot +0x6c, finalize the object, set UI state
//! to six, reinitialize the stream with the captured context, invoke the
//! manager-context operation, then finish the pending operation (1, 0).
//! Reload selector word +4 after the first record update: callees may mutate it.
//!
//! Deviations: host operations replace retail addresses. Firmware retains
//! retail getters because their Rust singleton constructors are incomplete;
//! all other calls also retain the verified retail paths (including IRAM
//! mirrors, not ROM). Preserve the final tail callee's r0 as a return word,
//! although both known callers discard it. No firmware behavior changes.

//! Verification: 14,020 host tests passed; ARM release build passed. Native
//! smoke confirmed selector reload, null-context preservation and completion
//! despite failure flags. match.py reports 36 original versus 52 emitted
//! instructions: absolute retail calls become BLX with pooled addresses;
//! both selector loads, saved context, call order and final BX remain.
//! No device execution.
#[derive(Clone, Copy)]
pub struct RecordSelectionCompleteOps {
    pub manager_get: unsafe extern "C" fn() -> *mut u8,
    pub begin: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
    pub context: unsafe extern "C" fn(*mut u8) -> *mut u8,
    pub records_get: unsafe extern "C" fn() -> *mut u8,
    pub status: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
    pub context_status: unsafe extern "C" fn(*mut u8, *mut u8, u32) -> u32,
    pub finalize: unsafe extern "C" fn(*mut u8, u32),
    pub set_state: unsafe extern "C" fn(*mut u8, u32),
    pub stream_get: unsafe extern "C" fn() -> *mut u8,
    pub reinitialize: unsafe extern "C" fn(*mut u8, u32, *mut u8) -> u32,
    pub context_operation: unsafe extern "C" fn(*mut u8),
    pub finish: unsafe extern "C" fn(*mut u8, u32, u32) -> u32,
}

#[cfg(not(target_os = "none"))]
pub static mut RECORD_SELECTION_COMPLETE_OPS: Option<RecordSelectionCompleteOps> = None;

/// # Safety
/// `object` has an aligned readable selector word at +4 and the layout and
/// vtable required by retail finalize @ 0x08202090. Retail global state must
/// be initialized. Host callers must install operations with exclusive access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_selection_complete(object: *mut u8, status: u32) -> u32 {
    #[cfg(target_os = "none")]
    let ops = RecordSelectionCompleteOps {
        manager_get: core::mem::transmute(0x0803_7f88usize), // ui_manager_acquire
        begin: core::mem::transmute(0x0803_8200usize), // ui_manager_begin_pending_operation
        context: core::mem::transmute(0x0803_8218usize), // ui_manager_current_context
        records_get: core::mem::transmute(0x081c_83b4usize), // record_manager_get
        status: core::mem::transmute(0x081c_8544usize), // record_manager_current_record_status_failed
        context_status: core::mem::transmute(0x081c_85c4usize), // record_manager_current_record_status_6c_failed
        finalize: core::mem::transmute(0x0820_2090usize), // virtual +0x20, +0x34; ready flag
        set_state: core::mem::transmute(0x0803_8228usize), // mirror 0x0800521c: state +0x28
        stream_get: core::mem::transmute(0x0803_7fd8usize), // iram_stream_buffer_initializer_veneer
        reinitialize: core::mem::transmute(0x0803_8190usize), // iram_stream_buffer_reinitialize_veneer
        context_operation: core::mem::transmute(0x0803_8220usize), // mirror 0x08004ee4: +0x1c -> 0x080ea540
        finish: core::mem::transmute(0x0803_8130usize), // ui_manager_finish_pending_operation
    };
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(RECORD_SELECTION_COMPLETE_OPS).read()
        .expect("install record-selection host operations");
    (ops.begin)((ops.manager_get)(), 1, 1);
    let context = (ops.context)((ops.manager_get)());
    let records = (ops.records_get)();
    (ops.status)(records, status, object.add(4).cast::<u32>().read_volatile());
    (ops.context_status)(records, context, object.add(4).cast::<u32>().read_volatile());
    (ops.finalize)(object, 1);
    (ops.set_state)((ops.manager_get)(), 6);
    (ops.reinitialize)((ops.stream_get)(), 0, context);
    (ops.context_operation)((ops.manager_get)());
    (ops.finish)((ops.manager_get)(), 1, 0)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::cell::RefCell;
    struct State { object: *mut u32, status: u32, selector: u32, stage: u32, context: u8 }
    std::thread_local! {
        static STATE: RefCell<State> = RefCell::new(State {
            object: core::ptr::null_mut(), status: 0, selector: 0, stage: 0, context: 0,
        });
    }
    unsafe extern "C" fn get() -> *mut u8 { core::ptr::null_mut() }
    unsafe extern "C" fn begin(_: *mut u8, a: u32, b: u32) -> u32 {
        assert_eq!((a,b),(1,1));
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,0); s.stage=1; });
        u32::MAX
    }
    unsafe extern "C" fn context(_: *mut u8) -> *mut u8 {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,1); s.stage=2; core::ptr::addr_of_mut!(s.context) })
    }
    unsafe extern "C" fn status(_: *mut u8, value: u32, selector: u32) -> u32 {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,2);
            assert_eq!((value,selector),(s.status,s.selector));
            s.object.add(1).write(!selector); s.stage=3;
        });
        1 // Failure flags do not short-circuit completion.
    }
    unsafe extern "C" fn context_status(_: *mut u8, context: *mut u8, selector: u32) -> u32 {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,3);
            assert_eq!(selector,!s.selector); assert_eq!(context,core::ptr::addr_of_mut!(s.context));
            context.write(0x73); s.stage=4;
        });
        1
    }
    unsafe extern "C" fn finalize(object: *mut u8, enabled: u32) {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,4);
            assert_eq!(object,s.object.cast()); assert_eq!(enabled,1); s.stage=5;
        });
    }
    unsafe extern "C" fn set_state(_: *mut u8, value: u32) {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,5); assert_eq!(value,6); s.stage=6; });
    }
    unsafe extern "C" fn reinitialize(_: *mut u8, zero: u32, context: *mut u8) -> u32 {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,6); assert_eq!(zero,0);
            assert_eq!(context,core::ptr::addr_of_mut!(s.context)); assert_eq!(context.read(),0x73); s.stage=7;
        });
        u32::MAX
    }
    unsafe extern "C" fn context_operation(_: *mut u8) {
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,7); s.stage=8; });
    }
    unsafe extern "C" fn finish(_: *mut u8, a: u32, b: u32) -> u32 {
        assert_eq!((a,b),(1,0));
        STATE.with(|s| { let mut s=s.borrow_mut(); assert_eq!(s.stage,8); s.stage=9; });
        0xfedc_ba98
    }
    #[test]
    fn reloads_mutated_selector_and_preserves_context_despite_failure_flags() {
        unsafe {
            let saved=core::ptr::addr_of!(RECORD_SELECTION_COMPLETE_OPS).read();
            RECORD_SELECTION_COMPLETE_OPS=Some(RecordSelectionCompleteOps {
                manager_get:get, begin, context, records_get:get, status, context_status,
                finalize, set_state, stream_get:get, reinitialize, context_operation, finish,
            });
            for value in [0,1,2,u32::MAX] {
                for selector in [0,1,0x8000_0000,u32::MAX] {
                    let mut object=[0xa5a5_a5a5,selector,0x1234_5678];
                    STATE.with(|s| *s.borrow_mut()=State { object:object.as_mut_ptr(), status:value, selector, stage:0, context:0 });
                    assert_eq!(record_selection_complete(object.as_mut_ptr().cast(),value),0xfedc_ba98);
                    assert_eq!(object,[0xa5a5_a5a5,!selector,0x1234_5678]);
                    STATE.with(|s| assert_eq!(s.borrow().stage,9));
                }
            }
            RECORD_SELECTION_COMPLETE_OPS=saved;
        }
    }
}
