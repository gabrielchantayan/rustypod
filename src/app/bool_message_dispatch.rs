//! Dispatches the fixed `Bool` message produced by a refcounted context.
//!
//! `dispatch_bool_message` — original: `FUN_08133ba8` @ `0x08133ba8`
//! (84 bytes, `0x08133ba8..0x08133bfc`: 76 bytes of instructions followed by
//! the two literal-pool words `0x00007682` and `0x426f6f6c`; the separately
//! linked function begins at `0x08133bfc`). Raw ARM decoding found **6 direct
//! `bl` callers, all unconditional; no predicated or tail-`b` callers**:
//! `0x08132d38`, `0x08132f04`, `0x0813333c`, `0x081334c4`, `0x08133520`, and
//! `0x08133594`.
//!
//! The routine replaces the context's owned refcounted handle at target
//! `+0x2c` from `source`, obtains one 16-byte block from the message-code-0x13
//! arena, then constructs `{ vtable=0x0898db3c, word1=0, type='Bool',
//! id=0x7682 }`. A nonzero `retain_message` dispatches that value through
//! `FUN_08124ff4` with `{ dispatch_enabled=1, reserved=1, extra=1 }`; zero
//! uses the ported `callback_dispatch_release`, which instead supplies
//! `{ 1, 0, 1 }` and releases the value afterwards.
//!
//! The stock `0x0839ef54` handle-assignment body is expressed with the
//! already ported, exact callee pair `refcounted_body_release_owned_variant`
//! (`0x0839cf4c`) and `refcounted_body_attach_owned_variant` (`0x0839cf10`).
//! The message constructor `0x081cd7b8` is inlined as its four recovered word
//! stores; this avoids creating a second dispatch seam for a simple
//! allocator-backed constructor. Host-only pool and vtable substitutions exist
//! solely to make the target-width message allocation and release path
//! observable in tests.

use crate::app::callback_dispatch_release::{
    callback_dispatch_release, DispatchValue, ValueDispatch,
};
use crate::app::message_0x13_arena::message_0x13_arena_pool;
use crate::cxx::handle::{
    refcounted_body_attach_owned_variant, refcounted_body_release_owned_variant, RefcountedBody,
};
use crate::heap::fixed_block_pool::{fixed_block_pool_alloc, FixedBlockPool};

const RETAIL_MESSAGE_0X13_VTABLE: u32 = 0x0898_db3c;
const BOOL_MESSAGE_TYPE: u32 = 0x426f_6f6c;
const BOOL_MESSAGE_ID: u32 = 0x0000_7682;
const VALUE_DISPATCH_ADDRESS: usize = 0x0812_4ff4;

/// The 16-byte message-code-0x13 object written by `FUN_081cd7b8`.
///
/// Every field is a u32 because the raw constructor stores target words at
/// `+0`, `+4`, `+8`, and `+0xc`; a host pointer would widen and misplace the
/// trailing fields.
#[repr(C)]
struct BoolMessage {
    vtable: u32,
    unresolved_04: u32,
    message_type: u32,
    message_id: u32,
}

/// Prefix of the receiver through its owned refcounted handle.
///
/// The first eleven target words are not identified. Keeping them as words
/// fixes `body` at target `+0x2c` while retaining a non-overlapping host
/// pointer field.
#[repr(C)]
pub struct BoolMessageContext {
    pub opaque_prefix: [u32; 11],
    pub body: *mut RefcountedBody,
}

type Message0x13Pool = unsafe extern "C" fn() -> *mut FixedBlockPool;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn message_pool() -> *mut FixedBlockPool {
    message_0x13_arena_pool()
}

#[cfg(not(target_os = "none"))]
static mut BOOL_MESSAGE_POOL: Message0x13Pool = message_0x13_arena_pool;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn message_pool() -> *mut FixedBlockPool {
    core::ptr::read_volatile(core::ptr::addr_of!(BOOL_MESSAGE_POOL))()
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn message_vtable() -> u32 {
    RETAIL_MESSAGE_0X13_VTABLE
}

#[cfg(not(target_os = "none"))]
static mut BOOL_MESSAGE_VTABLE: u32 = RETAIL_MESSAGE_0X13_VTABLE;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn message_vtable() -> u32 {
    core::ptr::read_volatile(core::ptr::addr_of!(BOOL_MESSAGE_VTABLE))
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn dispatch_without_release(context: *mut u8, value: *mut DispatchValue) -> u32 {
    let dispatch: ValueDispatch = core::mem::transmute(VALUE_DISPATCH_ADDRESS);
    dispatch(context, value, 1, 1, 1)
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn dispatch_without_release(context: *mut u8, value: *mut DispatchValue) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(
        crate::app::callback_dispatch_release::DISPATCH_AND_DESTROY_VALUE_OPS
    ));
    let dispatch = ops.dispatch;
    dispatch(context, value, 1, 1, 1)
}

/// dispatch_bool_message — original: `FUN_08133ba8` @ `0x08133ba8` (84 bytes;
/// 6 unconditional direct `bl` callers, no predicated or tail-`b` callers).
///
/// Replaces `context`'s owned handle from `source`, allocates and initializes
/// the fixed 16-byte `Bool` message, then dispatches it. `retain_message != 0`
/// selects the non-releasing `{1,1,1}` dispatch; zero selects the ported
/// releasing `{1,0,1}` wrapper.
///
/// # Safety
/// `context` and `source` must be readable target objects. The existing body
/// in `context`, the source body, the fixed pool, and the unported dispatcher
/// must satisfy their respective firmware contracts. The stock function does
/// not NULL-check either input object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn dispatch_bool_message(
    context: *mut BoolMessageContext,
    source: *const *mut RefcountedBody,
    retain_message: u32,
) -> u32 {
    let destination = core::ptr::addr_of_mut!((*context).body);
    if destination != source.cast_mut() {
        refcounted_body_release_owned_variant(destination);
        refcounted_body_attach_owned_variant(destination, source.read());
    }

    let message = fixed_block_pool_alloc(message_pool(), core::mem::size_of::<BoolMessage>())
        .cast::<BoolMessage>();
    message.write(BoolMessage {
        vtable: message_vtable(),
        unresolved_04: 0,
        message_type: BOOL_MESSAGE_TYPE,
        message_id: BOOL_MESSAGE_ID,
    });

    if retain_message != 0 {
        dispatch_without_release(context.cast(), message.cast())
    } else {
        callback_dispatch_release(context.cast(), message.cast(), 1)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::callback_dispatch_release::{
        DispatchAndDestroyValueOps, DispatchValueVtable, CALLBACK_DISPATCH_OPS_LOCK,
        DEFAULT_DISPATCH_AND_DESTROY_VALUE_OPS, DISPATCH_AND_DESTROY_VALUE_OPS,
    };
    use crate::heap::fixed_block_pool::FreeBlock;
    use crate::kernel::sync_mutex::Mutex;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of, addr_of_mut};

    const FIXTURE_LEN: usize = 0x1000;
    const MESSAGE_OFFSET: usize = 0;
    const VTABLE_OFFSET: usize = 0x100;

    static mut TEST_POOL: *mut FixedBlockPool = core::ptr::null_mut();
    static mut DISPATCH_CALL: Option<(*mut u8, *mut DispatchValue, u32, u32, u32)> = None;
    static mut FINALIZE_COUNT: u32 = 0;

    unsafe extern "C" fn test_message_pool() -> *mut FixedBlockPool {
        TEST_POOL
    }

    unsafe extern "C" fn record_dispatch(
        context: *mut u8,
        value: *mut DispatchValue,
        dispatch_enabled: u32,
        reserved: u32,
        extra: u32,
    ) -> u32 {
        DISPATCH_CALL = Some((context, value, dispatch_enabled, reserved, extra));
        0x71f0_0d13
    }

    unsafe extern "C" fn record_finalize(_value: *mut DispatchValue) {
        FINALIZE_COUNT += 1;
    }

    struct Fixture {
        base: *mut u8,
        pool: FixedBlockPool,
    }

    impl Fixture {
        fn new() -> Option<Self> {
            let base = try_map_u32_slab(hints::BOOL_MESSAGE_DISPATCH, FIXTURE_LEN)?;
            unsafe {
                base.write_bytes(0, FIXTURE_LEN);
                let message = base.add(MESSAGE_OFFSET).cast::<FreeBlock>();
                (*message).next = core::ptr::null_mut();
                let vtable = base.add(VTABLE_OFFSET).cast::<DispatchValueVtable>();
                vtable.write(DispatchValueVtable {
                    unresolved_00: 0,
                    finalize: record_finalize,
                });
                Some(Self {
                    base,
                    pool: FixedBlockPool {
                        lock: Mutex { sem_cell: core::ptr::null_mut(), unused: 0 },
                        block_size: core::mem::size_of::<BoolMessage>(),
                        block_count: 1,
                        total_bytes: core::mem::size_of::<BoolMessage>(),
                        storage: message.cast(),
                        free_head: message,
                    },
                })
            }
        }

        unsafe fn message(&self) -> *mut BoolMessage {
            self.base.add(MESSAGE_OFFSET).cast()
        }

        unsafe fn vtable(&self) -> *mut DispatchValueVtable {
            self.base.add(VTABLE_OFFSET).cast()
        }
    }

    struct TestState {
        previous_pool: Message0x13Pool,
        previous_vtable: u32,
        previous_ops: DispatchAndDestroyValueOps,
    }

    unsafe fn install(fixture: &mut Fixture) -> TestState {
        let previous_pool = addr_of!(BOOL_MESSAGE_POOL).read_volatile();
        let previous_vtable = addr_of!(BOOL_MESSAGE_VTABLE).read_volatile();
        let previous_ops = addr_of!(DISPATCH_AND_DESTROY_VALUE_OPS).read_volatile();
        TEST_POOL = addr_of_mut!(fixture.pool);
        BOOL_MESSAGE_POOL = test_message_pool;
        BOOL_MESSAGE_VTABLE = fixture.vtable() as usize as u32;
        DISPATCH_AND_DESTROY_VALUE_OPS = DispatchAndDestroyValueOps { dispatch: record_dispatch };
        DISPATCH_CALL = None;
        FINALIZE_COUNT = 0;
        TestState { previous_pool, previous_vtable, previous_ops }
    }

    unsafe fn restore(state: TestState) {
        DISPATCH_AND_DESTROY_VALUE_OPS = state.previous_ops;
        BOOL_MESSAGE_VTABLE = state.previous_vtable;
        BOOL_MESSAGE_POOL = state.previous_pool;
        TEST_POOL = core::ptr::null_mut();
    }

    fn run_case(retain_message: u32, source_is_destination: bool) {
        let _dispatch_lock = CALLBACK_DISPATCH_OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(mut fixture) = Fixture::new() else {
            assert!(note_missing_u32_fixture("app/bool_message_dispatch"));
            return;
        };
        let mut source_body = RefcountedBody {
            opaque0: 0,
            refcount: 3,
            mutex: core::ptr::null_mut(),
        };
        let mut source = addr_of_mut!(source_body);
        let mut context = BoolMessageContext {
            opaque_prefix: [0; 11],
            body: core::ptr::null_mut(),
        };
        let source_slot = if source_is_destination {
            context.body = source;
            addr_of!(context.body)
        } else {
            addr_of!(source)
        };
        unsafe {
            let state = install(&mut fixture);
            let result = dispatch_bool_message(addr_of_mut!(context), source_slot, retain_message);
            assert_eq!(result, 0x71f0_0d13);
            assert_eq!(context.body, source);
            assert_eq!(source_body.refcount, if source_is_destination { 3 } else { 4 });
            assert_eq!(
                addr_of!(DISPATCH_CALL).read(),
                Some((addr_of_mut!(context).cast(), fixture.message().cast(), 1, if retain_message != 0 { 1 } else { 0 }, 1))
            );
            assert_eq!((*fixture.message()).vtable, fixture.vtable() as usize as u32);
            assert_eq!((*fixture.message()).unresolved_04, 0);
            assert_eq!((*fixture.message()).message_type, BOOL_MESSAGE_TYPE);
            assert_eq!((*fixture.message()).message_id, BOOL_MESSAGE_ID);
            assert_eq!(FINALIZE_COUNT, if retain_message == 0 { 1 } else { 0 });
            restore(state);
        }
    }

    #[test]
    fn retaining_dispatch_keeps_the_message_after_bool_construction() {
        run_case(1, false);
    }

    #[test]
    fn identical_source_and_destination_preserve_the_refcount() {
        run_case(1, true);
    }

    #[test]
    fn nonretaining_dispatch_releases_the_constructed_message() {
        run_case(0, false);
    }
}
