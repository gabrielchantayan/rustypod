//! Port of the video-engine instance getter `FUN_08252bec` @ 0x08252bec
//! (12 bytes; 146 `bl` + 1 tail `b` call sites in osos, plus the alias
//! thunk `b 0x08252bec` @ 0x082cafbc) and of the public property-set
//! wrapper `FUN_082d2314` @ 0x082d2314 (48 bytes, 12 `bl` sites).
//!
//! Original:
//!
//! ```text
//! ldr r0, [0x8252bf8]      ; literal 0x089ca8a8 — instance slot
//! ldr r0, [r0, #0x0]       ; return *slot
//! bx  lr
//! ```
//!
//! A bare singleton getter: `return *(void **)0x089ca8a8`. Unlike the
//! lazily-constructed framework singletons (`app/singletons.rs`) this
//! one never allocates — the instance is created elsewhere and
//! installed through the setter @ 0x08252d4c (which releases the old
//! instance with flag 0 and retains the new one with flag 1 via
//! 0x0824ddf0), so a NULL return simply means "no video session" and
//! every one of the 146 callers checks for it.
//!
//! What the singleton is: the **video playback engine** instance.
//! The evidence, all from its own methods and installers:
//!
//! - Its only installer (0x082cb038, called from the media view
//!   controller's setup @ 0x08295ae0) is invoked while that view builds
//!   a **320x240 (0x140 x 0xf0)** display-layer-backed output path —
//!   the iPod Classic's screen size.
//! - The frame-advance method @ 0x08252aXX keeps a **ring of three
//!   frame slots** (index @ +0xab4, advanced mod 3): it picks the
//!   current, `(cur-1) mod 3` and `(cur-2) mod 3` slots (stride @
//!   +0xac8-derived), and feeds all three to the 1304-byte three-plane
//!   fixed-point (20.12) scaler/compositor @ 0x08251894 — the classic
//!   previous/current/next cadence of **temporal deinterlacing** of
//!   planar video.
//! - It carries a property bag keyed by 16-bit ids (0x8892 -> +0xad8,
//!   0x8893 -> +0xadc in the dispatcher @ 0x0825360c; 0x88e4/0x88e8 in
//!   0x0824ce14; 0x3059/0x305a -> +0xae0/+0xae4 in the query @
//!   0x082cafc8) with 0x500 as the unknown-property error code
//!   (0x0824f388), plus a byte flag word @ +0x14c and an "active" flag
//!   @ +0xb50 whose clearing tears down the frame buffer
//!   (0x0824ddf0 -> heap free of the block 0x0825642c returns).
//! - The public C wrappers @ 0x082d0c68..0x082d23ec are all
//!   `if (video_engine_get()) method(instance, ...)` thunks, which is
//!   where the bulk of the call sites come from.
//!
//! # Deviation
//!
//! On target the slot is read straight from the original firmware
//! address 0x089ca8a8 (the `kernel/control_state.rs` precedent): the
//! setter that owns the slot is unported, so the port must not keep its
//! own copy. Host builds substitute a mock pointer
//! (`set_mock_instance`) so the read-through behavior is testable.
//! Codegen on ARM is the same two-load leaf as the original.

#[cfg(not(target_arch = "arm"))]
use core::ptr::{addr_of, addr_of_mut};

/// Firmware address of the instance slot: the literal-pool word the
/// original's first `ldr` fetches (0x089ca8a8).
#[cfg(target_arch = "arm")]
const INSTANCE_SLOT_ADDR: u32 = 0x089c_a8a8;

/// Host-test stand-in for the firmware instance slot @ 0x089ca8a8.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_INSTANCE: *mut u8 = core::ptr::null_mut();

/// Host only: install the pointer the getter will return.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_instance(instance: *mut u8) {
    *addr_of_mut!(MOCK_INSTANCE) = instance;
}

#[inline]
fn instance() -> *mut u8 {
    #[cfg(target_arch = "arm")]
    unsafe {
        (INSTANCE_SLOT_ADDR as *const *mut u8).read_volatile()
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        *addr_of!(MOCK_INSTANCE)
    }
}

/// video_engine_get — original: `FUN_08252bec` @ 0x08252bec (12 bytes).
///
/// Returns the video-engine instance @ *0x089ca8a8, or NULL when no
/// video session is installed (the case every caller checks for).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_get() -> *mut u8 {
    instance()
}

/// Firmware address of the property dispatcher the wrapper tail-calls
/// (`FUN_08250498` @ 0x08250498, unported).
#[cfg(target_arch = "arm")]
const PROPERTY_DISPATCH_ADDR: usize = 0x0825_0498;

/// Host-test stand-in for the property dispatcher @ 0x08250498. `None`
/// panics if reached — the wrapper must never dispatch without an
/// instance, and tests assert that.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_DISPATCH: Option<unsafe extern "C" fn(*mut u8, u32, u32, u32)> = None;

/// Host only: install the mock the wrapper dispatches to.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_dispatch(
    dispatch: Option<unsafe extern "C" fn(*mut u8, u32, u32, u32)>,
) {
    *addr_of_mut!(MOCK_DISPATCH) = dispatch;
}

/// Tail dispatch into the (unported) property dispatcher @ 0x08250498.
fn property_dispatch(engine: *mut u8, command: u32, key: u32, value: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        let dispatch: unsafe extern "C" fn(*mut u8, u32, u32, u32) =
            core::mem::transmute(PROPERTY_DISPATCH_ADDR);
        dispatch(engine, command, key, value)
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        match *addr_of!(MOCK_DISPATCH) {
            Some(dispatch) => dispatch(engine, command, key, value),
            None => panic!("video_engine_set_property requires dispatcher 0x08250498"),
        }
    }
}

/// video_engine_set_property — original: `FUN_082d2314` @ 0x082d2314
/// (48 bytes; 12 `bl` call sites in osos, all plain `bl`, none
/// predicated — verified by a B/BL scan of osos.dec).
///
/// Public C wrapper that submits a property-set command to the video
/// engine when a session is installed:
///
/// ```text
/// push {r4, r5, r6, lr}
/// mov   r6, r2               ; value
/// mov   r5, r1               ; key
/// mov   r4, r0               ; command
/// bl    0x08252bec           ; video_engine_get
/// cmp   r0, #0
/// movne r3, r6
/// movne r2, r5
/// movne r1, r4
/// popne {r4, r5, r6, lr}
/// bne   0x08250498           ; tail: dispatch(instance, command, key, value)
/// pop   {r4, r5, r6, pc}     ; NULL instance: silent no-op
/// ```
///
/// `if (video_engine_get()) dispatch(instance, command, key, value)` —
/// no session, no error, no latch: a NULL instance is simply ignored.
///
/// The tail target `FUN_08250498` @ 0x08250498 is the engine's property
/// dispatcher: it rejects any `command != 0xde1` by latching the
/// unknown-property error code 0x500 through `latch_first_error`
/// (0x0824f388, ported in util/error_latch). For `command == 0xde1` it
/// resolves the current frame slot (0x08252bfc: `slot =
/// instance->table[instance->index]`, table @ +0xa8c, index @ +0x24c)
/// and writes one parameter byte keyed by `key`: 0x2800 -> slot+0x105
/// (1 for value 0x2600, 2 for 0x2601), 0x2801 -> slot+0x104 and
/// slot+0x106 (maps values 0x2600/0x2601/0x2700/0x2701/0x2702),
/// 0x2802 -> slot+0x107 and 0x2803 -> slot+0x108 (via the resolver
/// 0x08260448), 0x8191 -> the instance bool @ +0x90a; unknown
/// key/value pairs also latch 0x500. All 12 call sites pass command
/// 0xde1: six in the engine setup @ 0x0825bd98 (as 0x201 + 0xbe0; keys
/// 0x2800/0x2801/0x2802/0x2803 with values 0x2600/0x2601/0x812f — the
/// 0x2802/0x2803 keys computed as `0x2801 ^| 0xde1 >> 10`), six in the
/// 0x08281030 cluster (literal 0xde1).
///
/// # Deviation
///
/// The dispatcher @ 0x08250498 is unported: on target the wrapper calls
/// the original firmware body through its address (the
/// `core::mem::transmute` seam of app/command_dispatch.rs); host tests
/// install a recording mock via `set_mock_dispatch`. The NULL-instance
/// no-op path never touches the seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_set_property(command: u32, key: u32, value: u32) {
    let engine = video_engine_get();
    if engine.is_null() {
        return;
    }
    property_dispatch(engine, command, key, value);
}
/// Firmware entry of the video-engine control-code enabler
/// (`FUN_08252be4`, unported).
#[cfg(target_arch = "arm")]
const VIDEO_ENGINE_ENABLE_CONTROL_ADDR: usize = 0x0825_2be4;

/// ABI of the engine helper that receives an engine, a control code, and
/// the literal enable value one.
type VideoEngineEnableControl = unsafe extern "C" fn(*mut u8, u32, u32);

/// Host-test stand-in for `FUN_08252be4`.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_ENABLE_CONTROL: Option<VideoEngineEnableControl> = None;

/// Host only: install the control-code enabler reached by the wrapper.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_enable_control(
    enable_control: Option<VideoEngineEnableControl>,
) {
    *addr_of_mut!(MOCK_ENABLE_CONTROL) = enable_control;
}

/// Transfers an enabled control code into the engine's unported handler.
fn enable_control(engine: *mut u8, control: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        let enable_control: VideoEngineEnableControl =
            core::mem::transmute(VIDEO_ENGINE_ENABLE_CONTROL_ADDR);
        enable_control(engine, control, 1);
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        match *addr_of!(MOCK_ENABLE_CONTROL) {
            Some(enable_control) => enable_control(engine, control, 1),
            None => panic!("video_engine_enable_control requires handler 0x08252be4"),
        }
    }
}

/// video_engine_enable_control — retailOS `FUN_082d12b0` @ **0x082d12b0**
/// (32 bytes, `0x082d12b0..0x082d12cc`). Raw bytes show that the next
/// independently linked function starts at `0x082d12d0`; Ghidra's reported
/// 40-byte extent incorrectly includes its first eight bytes. A complete
/// aligned ARM B/BL-immediate decode finds seven direct inbound calls, all
/// `bleq` (zero plain `bl`): 0x0827d3e0, 0x0827d4c0, 0x0827d5b4,
/// 0x0828ca88, 0x0828caec, 0x083d38d4, and 0x083d39b4. Each caller gates
/// this wrapper on its own equality condition.
///
/// Loads the video-engine singleton, returns silently if no session exists,
/// then tail-transfers `(engine, control, 1)` to `FUN_08252be4`. That helper
/// enables the control-code-specific engine flag: codes 0x8074, 0x8075,
/// 0x8076, and 0x8b9c set bits 0 through 3 in the byte at `engine + 0x14c`;
/// 0x8078 sets the byte at `engine + engine[0x250] + 0x14d`; other codes
/// reach its 0x500 error latch.
///
/// # Deliberate deviation
///
/// `FUN_08252be4` is unported. Target builds call its resident firmware
/// entry directly; host tests install a recording handler. The NULL-session
/// path never accesses that seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_enable_control(control: u32) {
    let engine = video_engine_get();
    if engine.is_null() {
        return;
    }
    enable_control(engine, control);
}
/// Firmware entry of the 8-byte enable veneer `FUN_08253f58`.
///
/// The veneer sets `r2 = 1` and tail-branches to the unported code-addressed
/// flag handler `FUN_08254198`.
#[cfg(target_arch = "arm")]
const VIDEO_ENGINE_ENABLE_FLAG_ADDR: usize = 0x0825_3f58;

/// ABI of the enable veneer: video-engine instance followed by a flag code.
type VideoEngineEnableFlag = unsafe extern "C" fn(*mut u8, u32);

/// Host-test stand-in for the enable veneer @ 0x08253f58.
#[cfg(not(target_arch = "arm"))]
static mut MOCK_ENABLE_FLAG: Option<VideoEngineEnableFlag> = None;

/// Host only: install the mock reached by `video_engine_enable_flag`.
#[cfg(not(target_arch = "arm"))]
pub unsafe fn set_mock_enable_flag(enable_flag: Option<VideoEngineEnableFlag>) {
    *addr_of_mut!(MOCK_ENABLE_FLAG) = enable_flag;
}

/// Transfers a video-engine flag code to the original enable veneer.
fn enable_flag(engine: *mut u8, flag: u32) {
    #[cfg(target_arch = "arm")]
    unsafe {
        let enable_flag: VideoEngineEnableFlag =
            core::mem::transmute(VIDEO_ENGINE_ENABLE_FLAG_ADDR);
        enable_flag(engine, flag);
    }
    #[cfg(not(target_arch = "arm"))]
    unsafe {
        match *addr_of!(MOCK_ENABLE_FLAG) {
            Some(enable_flag) => enable_flag(engine, flag),
            None => panic!("video_engine_enable_flag requires veneer 0x08253f58"),
        }
    }
}

/// video_engine_enable_flag — retailOS `FUN_082d1290` @ **0x082d1290**
/// (32 bytes, `0x082d1290..0x082d12ac`). Raw bytes show the next
/// independently linked function begins at `0x082d12b0`; Ghidra's reported
/// 40-byte body instead merges this wrapper into its neighbors. Complete
/// aligned ARM B/BL-immediate decoding finds seven inbound `bl` calls: five
/// plain `bl` at 0x08142c30, 0x0825bf64, 0x0825bf90, 0x082742e4, and
/// 0x0827d52c, plus two caller-gated `bleq` calls at 0x0827d42c and
/// 0x08281164. No aligned data word holds this address.
///
/// Loads the video-engine singleton and silently returns for a NULL session.
/// Otherwise it tail-branches with `(engine, flag)` to `FUN_08253f58`, the
/// 8-byte veneer that inserts the literal enable value one before transferring
/// to the unported code-addressed flag handler `FUN_08254198`. The wrapper
/// performs no validation: every flag value reaches that veneer unchanged.
///
/// # Deliberate deviation
///
/// The final handler is unported. Target builds call the verified veneer at
/// 0x08253f58 directly; host tests install a recording seam. The NULL-session
/// path never accesses the seam.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_enable_flag(flag: u32) {
    let engine = video_engine_get();
    if engine.is_null() {
        return;
    }
    enable_flag(engine, flag);
}

/// Firmware entry of the video-engine one-handle release helper
/// `FUN_082d1134`.
#[cfg(target_os = "none")]
const VIDEO_ENGINE_RELEASE_ONE_HANDLE_ADDR: usize = 0x082d_1134;

/// ABI of the still-unported video-engine one-handle release helper.
type VideoEngineReleaseOneHandle = unsafe extern "C" fn(usize, *mut u32);

/// Target transfer into `FUN_082d1134`.
#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn video_engine_release_one_handle(handle: *mut u32) {
    let release: VideoEngineReleaseOneHandle =
        core::mem::transmute(VIDEO_ENGINE_RELEASE_ONE_HANDLE_ADDR);
    release(1, handle);
}

/// Host boundary for the still-unported one-handle release helper.
#[cfg(not(target_os = "none"))]
static mut MOCK_RELEASE_ONE_HANDLE: Option<VideoEngineReleaseOneHandle> = None;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn video_engine_release_one_handle(handle: *mut u32) {
    match core::ptr::addr_of!(MOCK_RELEASE_ONE_HANDLE).read() {
        Some(release) => release(1, handle),
        None => panic!("video_engine_release_one_handle_and_delete requires helper 0x082d1134"),
    }
}

/// video_engine_release_one_handle_and_delete — retailOS `FUN_08272800` @
/// **0x08272800** (28 bytes; `0x08272800..0x08272818`). The next distinct
/// function begins at `0x0827281c`.
///
/// Raw ARM is `push {r4,lr}; mov r4,r1; mov r0,#1; bl 0x082d1134; mov r0,r4;
/// pop {r4,lr}; b 0x082aad24`: it discards its first argument, releases the
/// one-word handle supplied in `r1` through the video-engine helper, then
/// tail-transfers that same allocation to tag-2 `operator_delete`. There is no
/// NULL guard before the release helper. A full osos.dec ARM B/BL decode finds
/// 8 inbound calls: 4 plain `bl` (0x0827ba6c, 0x0827ba84, 0x0827bc88,
/// 0x0828e6a8) and 4 `blne` (0x0827bd38, 0x0827bd48, 0x0827bd58,
/// 0x0827bd68); the predicated callers gate the call on their own non-NULL
/// handle loads. No aligned DATA word references this entry.
///
/// Deliberate deviation: `FUN_082d1134` is not ported. Target builds call its
/// resident firmware address directly; host builds use the narrow recording
/// boundary above. `operator_delete` is already ported and called directly.
///
/// # Safety
///
/// `handle` is forwarded without validation to `FUN_082d1134`, then to the
/// allocator. The first argument is intentionally ignored, as in the raw ARM.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_release_one_handle_and_delete(
    _unused: *mut u8,
    handle: *mut u32,
) {
    video_engine_release_one_handle(handle);
    crate::heap::veneers::operator_delete(handle.cast());
}

/// ABI of the frame-operation callback selected by the video engine.
pub type VideoFrameOperationDispatch =
    unsafe extern "C" fn(context: *mut u8, frame: *mut u8, operation: u32);

/// Host-width table used when the engine selects a callback indirectly.
///
/// The target table consists of 32-bit callback words.  Native function
/// pointers are wider on the host, so this representation preserves table-slot
/// roles rather than target byte offsets.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct VideoFrameOperationDispatchTable {
    pub entries: [VideoFrameOperationDispatch; 2],
}

/// Host-width prefix of the video-engine fields this operation needs.
///
/// On target the two words at `+0xa94` and `+0xa98` are `u32`.  The first is
/// either a direct callback word or an indirect-table byte offset, selected by
/// the low tag bit of the second.  The host representation widens the callback
/// word while retaining its two roles and the signed-half context calculation.
#[cfg(not(target_arch = "arm"))]
#[repr(C)]
pub struct VideoFrameOperationEngine {
    /// The table pointer read from the selected dispatch context in indirect mode.
    pub dispatch_table: *const VideoFrameOperationDispatchTable,
    _before_dispatch_target: [u8; 0xa94 - core::mem::size_of::<usize>()],
    /// Direct callback, or byte offset into `dispatch_table` with low bits ignored.
    pub dispatch_target_or_table_offset: usize,
    /// Low bit selects indirect mode; arithmetic half is added to this engine.
    pub dispatch_selector: i32,
}
/// Target-width prefix of a video frame's operation-state word.
#[repr(C)]
struct VideoFrameOperationState {
    _before_pending_operations: [u8; 0x90],
    pending_operations: u32,
}

/// Reads the operation callback selection and invokes its resulting callback.
///
/// `video_frame_dispatch_operation` — original: `FUN_0824f1e8` @
/// **0x0824f1e8** (96 bytes, `0x0824f1e8..0x0824f248`; raw decode confirms
/// the next separately linked function begins at `0x0824f248`). A complete
/// decode of every ARM `B`/`BL` immediate in `osos.dec` finds **9 direct
/// `bl` call sites, all unconditional**: 0x0824d720, 0x0824d768,
/// 0x0824dc00, 0x0824dc1c, 0x0824dc2c, 0x0824dc3c, 0x08251b94,
/// 0x08251bb0, and 0x08251bc0. No immediate `blx`, predicated call, direct
/// tail branch, or aligned data word targets this entry.
///
/// If frame `+0x90` already shares either low operation bit with `operation`,
/// it returns without dispatching. Otherwise it computes the callback context
/// as `engine + (dispatch_selector as i32 >> 1)`. A clear selector tag calls
/// the callback word at engine `+0xa94`; a set tag treats that word (with its
/// low two bits cleared) as an offset into the table pointed to by the context's
/// first word. It re-reads frame `+0x90` after the callback, then ORs
/// `operation & 3` into that live value. The callback gets the complete,
/// unmasked operation word.
///
/// # Safety
///
/// `engine`, `frame`, and every selected context/table/callback must meet the
/// unguarded retailOS pointer contract. A callback may mutate either object;
/// its frame `+0x90` mutation is preserved because the final OR starts from
/// the post-callback reload.
///
/// # Deliberate deviation
///
/// Target builds read exactly the recovered 32-bit fields. Host builds use
/// [`VideoFrameOperationEngine`] and
/// [`VideoFrameOperationDispatchTable`] so native-width callback pointers are
/// not truncated. A target byte offset is converted to a table word index on
/// the host; the named fields retain the target's callback-selection roles and
/// signed-half context rule.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_frame_dispatch_operation(
    engine: *mut u8,
    frame: *mut u8,
    operation: u32,
) {
    let frame_state = frame.cast::<VideoFrameOperationState>();
    let pending_operations = core::ptr::read_volatile(core::ptr::addr_of!((*frame_state).pending_operations));
    if pending_operations & operation & 3 != 0 {
        return;
    }

    #[cfg(target_arch = "arm")]
    {
        let dispatch_selector =
            core::ptr::read_volatile(engine.byte_add(0xa98).cast::<u32>());
        let context = engine.byte_offset((dispatch_selector as i32 >> 1) as isize);
        let callback_address = if dispatch_selector & 1 != 0 {
            let table_address = core::ptr::read_volatile(context.cast::<u32>());
            let table_offset =
                core::ptr::read_volatile(engine.byte_add(0xa94).cast::<u32>()) & !3;
            core::ptr::read_volatile((table_address as *const u8).byte_add(table_offset as usize).cast::<u32>())
        } else {
            core::ptr::read_volatile(engine.byte_add(0xa94).cast::<u32>())
        };
        let callback: VideoFrameOperationDispatch = core::mem::transmute(callback_address as usize);
        callback(context, frame, operation);
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let host_engine = &*engine.cast::<VideoFrameOperationEngine>();
        let context = engine.byte_offset((host_engine.dispatch_selector >> 1) as isize);
        let callback = if host_engine.dispatch_selector & 1 != 0 {
            let table = core::ptr::read_volatile(context.cast::<*const VideoFrameOperationDispatchTable>());
            let table_index = (host_engine.dispatch_target_or_table_offset & !3) / 4;
            core::ptr::read_volatile(core::ptr::addr_of!((*table).entries[table_index]))
        } else {
            core::mem::transmute(host_engine.dispatch_target_or_table_offset)
        };
        callback(context, frame, operation);
    }

    let pending_operations = core::ptr::read_volatile(core::ptr::addr_of!((*frame_state).pending_operations));
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*frame_state).pending_operations),
        pending_operations | (operation & 3),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn returns_null_before_any_instance_is_installed() {
        unsafe {
            set_mock_instance(ptr::null_mut());
            assert!(video_engine_get().is_null());
        }
    }

    #[test]
    fn returns_the_installed_instance_exactly() {
        let mut object = [0xa5u8; 16];
        unsafe {
            set_mock_instance(object.as_mut_ptr());
            assert_eq!(video_engine_get(), object.as_mut_ptr());
        }
    }

    #[test]
    fn every_call_re_reads_the_slot() {
        // The setter swaps the instance at runtime (release old /
        // retain new), so the getter must not cache: a second call
        // after a swap sees the new pointer, and NULL after teardown.
        let mut first = [0xa5u8; 16];
        let mut second = [0x5au8; 16];
        unsafe {
            set_mock_instance(first.as_mut_ptr());
            assert_eq!(video_engine_get(), first.as_mut_ptr());
            set_mock_instance(second.as_mut_ptr());
            assert_eq!(video_engine_get(), second.as_mut_ptr());
            set_mock_instance(ptr::null_mut());
            assert!(video_engine_get().is_null());
        }
    }

    #[test]
    fn the_returned_pointer_is_not_dereferenced() {
        // A bare getter: the object's contents are irrelevant to it.
        let mut object = [0u8; 16];
        unsafe {
            set_mock_instance(object.as_mut_ptr());
            assert_eq!(video_engine_get(), object.as_mut_ptr());
            assert_eq!(object, [0u8; 16], "the object is untouched");
        }
    }

    // --- video_engine_set_property (FUN_082d2314) ---

    /// Serializes the set_property tests: MOCK_INSTANCE is shared with
    /// the getter tests above and MOCK_DISPATCH/RECORDED are shared
    /// between these tests.
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static mut RECORDED: Option<(*mut u8, u32, u32, u32)> = None;

    unsafe extern "C" fn recording_dispatch(
        engine: *mut u8,
        command: u32,
        key: u32,
        value: u32,
    ) {
        *addr_of_mut!(RECORDED) = Some((engine, command, key, value));
    }

    unsafe fn recorded() -> Option<(*mut u8, u32, u32, u32)> {
        *addr_of!(RECORDED)
    }

    #[test]
    fn null_instance_is_a_silent_no_op() {
        let _guard = LOCK.lock();
        unsafe {
            *addr_of_mut!(RECORDED) = None;
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(ptr::null_mut());
            // Must not dispatch, must not error, must not panic.
            video_engine_set_property(0xde1, 0x2801, 0x2600);
            assert_eq!(recorded(), None, "no dispatch without a session");
        }
    }

    #[test]
    fn dispatches_with_instance_prepended_and_args_verbatim() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            *addr_of_mut!(RECORDED) = None;
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(engine.as_mut_ptr());
            video_engine_set_property(0xde1, 0x2801, 0x2600);
            assert_eq!(
                recorded(),
                Some((engine.as_mut_ptr(), 0xde1, 0x2801, 0x2600)),
                "instance first, command/key/value unchanged"
            );
        }
    }

    #[test]
    fn edge_values_pass_through_unmodified() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(engine.as_mut_ptr());
            for &(command, key, value) in &[
                (0, 0, 0),
                (0xde1, 0x8191, 1),
                (0xffff_ffff, 0xffff_ffff, 0xffff_ffff),
                (0xde1, 0x2803, 0x812f),
            ] {
                *addr_of_mut!(RECORDED) = None;
                video_engine_set_property(command, key, value);
                assert_eq!(
                    recorded(),
                    Some((engine.as_mut_ptr(), command, key, value)),
                    "the wrapper is a pure pass-through; validation is the dispatcher's job"
                );
            }
        }
    }

    #[test]
    fn the_instance_is_re_read_for_every_call() {
        let _guard = LOCK.lock();
        let mut first = [0u8; 16];
        let mut second = [0u8; 16];
        unsafe {
            set_mock_dispatch(Some(recording_dispatch));
            set_mock_instance(first.as_mut_ptr());
            *addr_of_mut!(RECORDED) = None;
            video_engine_set_property(0xde1, 0x2800, 0x2600);
            assert_eq!(recorded().map(|r| r.0), Some(first.as_mut_ptr()));
            // The setter can swap or tear down the session at runtime.
            set_mock_instance(second.as_mut_ptr());
            *addr_of_mut!(RECORDED) = None;
            video_engine_set_property(0xde1, 0x2800, 0x2601);
            assert_eq!(recorded().map(|r| r.0), Some(second.as_mut_ptr()));
            set_mock_instance(ptr::null_mut());
            *addr_of_mut!(RECORDED) = None;
            video_engine_set_property(0xde1, 0x2800, 0x2601);
            assert_eq!(recorded(), None, "teardown stops the dispatch");
        }
    }
    // --- video_engine_enable_control (FUN_082d12b0) ---

    static mut ENABLE_CONTROL_RECORDED: Option<(*mut u8, u32, u32)> = None;

    unsafe extern "C" fn record_enable_control(engine: *mut u8, control: u32, enabled: u32) {
        *addr_of_mut!(ENABLE_CONTROL_RECORDED) = Some((engine, control, enabled));
    }

    #[test]
    fn enabling_control_without_a_session_is_a_silent_no_op() {
        let _guard = LOCK.lock();
        unsafe {
            *addr_of_mut!(ENABLE_CONTROL_RECORDED) = None;
            set_mock_enable_control(Some(record_enable_control));
            set_mock_instance(ptr::null_mut());
            video_engine_enable_control(0x8074);
            assert_eq!(
                ENABLE_CONTROL_RECORDED,
                None,
                "the handler is not reached without an engine"
            );
        }
    }

    #[test]
    fn enabling_control_forwards_engine_code_and_literal_one() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            set_mock_enable_control(Some(record_enable_control));
            set_mock_instance(engine.as_mut_ptr());
            for &control in &[0, 0x8074, 0x8075, 0x8076, 0x8078, 0x8b9c, u32::MAX] {
                *addr_of_mut!(ENABLE_CONTROL_RECORDED) = None;
                video_engine_enable_control(control);
                assert_eq!(
                    ENABLE_CONTROL_RECORDED,
                    Some((engine.as_mut_ptr(), control, 1)),
                    "the wrapper preserves each control code and always enables it"
                );
            }
        }
    }

    // --- video_engine_enable_flag (FUN_082d1290) ---

    static mut ENABLE_FLAG_RECORDED: Option<(*mut u8, u32)> = None;

    unsafe extern "C" fn record_enable_flag(engine: *mut u8, flag: u32) {
        *addr_of_mut!(ENABLE_FLAG_RECORDED) = Some((engine, flag));
    }

    #[test]
    fn enabling_flag_without_a_session_is_a_silent_no_op() {
        let _guard = LOCK.lock();
        unsafe {
            *addr_of_mut!(ENABLE_FLAG_RECORDED) = None;
            set_mock_enable_flag(Some(record_enable_flag));
            set_mock_instance(ptr::null_mut());
            video_engine_enable_flag(0x3000);
            assert_eq!(
                ENABLE_FLAG_RECORDED,
                None,
                "the enable veneer is not reached without an engine"
            );
        }
    }

    #[test]
    fn enabling_flag_forwards_engine_and_every_flag_value_verbatim() {
        let _guard = LOCK.lock();
        let mut engine = [0u8; 16];
        unsafe {
            set_mock_enable_flag(Some(record_enable_flag));
            set_mock_instance(engine.as_mut_ptr());
            for &flag in &[0, 0xb10, 0xbc0, 0x3000, 0x3002, u32::MAX] {
                *addr_of_mut!(ENABLE_FLAG_RECORDED) = None;
                video_engine_enable_flag(flag);
                assert_eq!(
                    ENABLE_FLAG_RECORDED,
                    Some((engine.as_mut_ptr(), flag)),
                    "the wrapper prepends the engine and leaves flag validation to the handler"
                );
            }
        }
    }


    // --- video_frame_dispatch_operation (FUN_0824f1e8) ---

    static mut FRAME_OPERATION_RECORDED: Option<(*mut u8, *mut u8, u32)> = None;

    unsafe extern "C" fn record_frame_operation(
        context: *mut u8,
        frame: *mut u8,
        operation: u32,
    ) {
        *addr_of_mut!(FRAME_OPERATION_RECORDED) = Some((context, frame, operation));
    }

    unsafe extern "C" fn replace_pending_operations(
        _context: *mut u8,
        frame: *mut u8,
        _operation: u32,
    ) {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*frame.cast::<VideoFrameOperationState>()).pending_operations),
            0x80,
        );
    }

    unsafe extern "C" fn unexpected_frame_operation(
        _context: *mut u8,
        _frame: *mut u8,
        _operation: u32,
    ) {
        panic!("masked table offset selected the wrong operation callback");
    }

    fn operation_frame(pending_operations: u32) -> VideoFrameOperationState {
        VideoFrameOperationState {
            _before_pending_operations: [0; 0x90],
            pending_operations,
        }
    }

    #[test]
    fn frame_operation_dispatches_direct_callback_and_latches_low_operation_bits() {
        let _guard = LOCK.lock();
        let mut frame = operation_frame(2);
        let mut engine = VideoFrameOperationEngine {
            dispatch_table: ptr::null(),
            _before_dispatch_target: [0; 0xa94 - core::mem::size_of::<usize>()],
            dispatch_target_or_table_offset: record_frame_operation as usize,
            dispatch_selector: 0,
        };

        unsafe {
            *addr_of_mut!(FRAME_OPERATION_RECORDED) = None;
            video_frame_dispatch_operation(
                (&mut engine as *mut VideoFrameOperationEngine).cast(),
                (&mut frame as *mut VideoFrameOperationState).cast(),
                0x8000_0001,
            );
            assert_eq!(
                FRAME_OPERATION_RECORDED,
                Some((
                    (&mut engine as *mut VideoFrameOperationEngine).cast(),
                    (&mut frame as *mut VideoFrameOperationState).cast(),
                    0x8000_0001,
                )),
                "the callback receives context/frame and the full operation word"
            );
            assert_eq!(frame.pending_operations, 3, "only low operation bits latch");
        }
    }

    #[test]
    fn frame_operation_latches_against_callback_updated_pending_state() {
        let _guard = LOCK.lock();
        let mut frame = operation_frame(0);
        let mut engine = VideoFrameOperationEngine {
            dispatch_table: ptr::null(),
            _before_dispatch_target: [0; 0xa94 - core::mem::size_of::<usize>()],
            dispatch_target_or_table_offset: replace_pending_operations as usize,
            dispatch_selector: 0,
        };

        unsafe {
            video_frame_dispatch_operation(
                (&mut engine as *mut VideoFrameOperationEngine).cast(),
                (&mut frame as *mut VideoFrameOperationState).cast(),
                1,
            );
            assert_eq!(
                frame.pending_operations, 0x81,
                "the final latch reloads the callback-mutated pending word"
            );
        }
    }

    #[test]
    fn frame_operation_uses_tagged_table_offset_and_skips_an_already_pending_operation() {
        let _guard = LOCK.lock();
        let table = VideoFrameOperationDispatchTable {
            entries: [unexpected_frame_operation, record_frame_operation],
        };
        let mut engine = VideoFrameOperationEngine {
            dispatch_table: &table,
            _before_dispatch_target: [0; 0xa94 - core::mem::size_of::<usize>()],
            dispatch_target_or_table_offset: 7,
            dispatch_selector: 1,
        };
        let mut frame = operation_frame(0x40);

        unsafe {
            *addr_of_mut!(FRAME_OPERATION_RECORDED) = None;
            video_frame_dispatch_operation(
                (&mut engine as *mut VideoFrameOperationEngine).cast(),
                (&mut frame as *mut VideoFrameOperationState).cast(),
                2,
            );
            assert_eq!(
                FRAME_OPERATION_RECORDED,
                Some((
                    (&mut engine as *mut VideoFrameOperationEngine).cast(),
                    (&mut frame as *mut VideoFrameOperationState).cast(),
                    2,
                )),
                "tagged indirect mode masks low table-offset bits"
            );
            assert_eq!(frame.pending_operations, 0x42);

            *addr_of_mut!(FRAME_OPERATION_RECORDED) = None;
            video_frame_dispatch_operation(
                (&mut engine as *mut VideoFrameOperationEngine).cast(),
                (&mut frame as *mut VideoFrameOperationState).cast(),
                2,
            );
            assert_eq!(
                FRAME_OPERATION_RECORDED,
                None,
                "an overlapping low pending bit suppresses the callback"
            );
            assert_eq!(frame.pending_operations, 0x42);
        }
    }

    #[test]
    fn zero_operation_still_dispatches_without_changing_pending_bits() {
        let _guard = LOCK.lock();
        let mut frame = operation_frame(0xffff_fffc);
        let mut engine = VideoFrameOperationEngine {
            dispatch_table: ptr::null(),
            _before_dispatch_target: [0; 0xa94 - core::mem::size_of::<usize>()],
            dispatch_target_or_table_offset: record_frame_operation as usize,
            dispatch_selector: 0,
        };

        unsafe {
            *addr_of_mut!(FRAME_OPERATION_RECORDED) = None;
            video_frame_dispatch_operation(
                (&mut engine as *mut VideoFrameOperationEngine).cast(),
                (&mut frame as *mut VideoFrameOperationState).cast(),
                0,
            );
            assert_eq!(
                FRAME_OPERATION_RECORDED.map(|record| record.2),
                Some(0),
                "zero has no low pending bits, so it is dispatched"
            );
            assert_eq!(frame.pending_operations, 0xffff_fffc);
        }
    }
    // --- video_engine_release_one_handle_and_delete (FUN_08272800) ---

    static mut RELEASED_ONE_HANDLE: Option<(usize, *mut u32)> = None;
    static mut DELETED_HANDLE: Option<(*mut u8, usize)> = None;

    unsafe extern "C" fn record_release_one_handle(count: usize, handle: *mut u32) {
        *addr_of_mut!(RELEASED_ONE_HANDLE) = Some((count, handle));
    }

    unsafe extern "C" fn record_operator_delete(
        _heap: *mut crate::heap::types::HeapDescriptorDescriptor,
        handle: *mut u8,
        tag: usize,
    ) {
        *addr_of_mut!(DELETED_HANDLE) = Some((handle, tag));
    }

    struct ReleaseAndDeleteReset {
        release: Option<VideoEngineReleaseOneHandle>,
        heap_ops: crate::heap::veneers::HeapVeneerOps,
    }

    impl Drop for ReleaseAndDeleteReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(MOCK_RELEASE_ONE_HANDLE).write(self.release);
                core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(self.heap_ops);
            }
        }
    }

    unsafe fn record_release_and_delete() -> ReleaseAndDeleteReset {
        let release = core::ptr::addr_of!(MOCK_RELEASE_ONE_HANDLE).read();
        let heap_ops = core::ptr::addr_of!(crate::heap::veneers::HEAP_OPS).read_volatile();
        let mut recording_heap_ops = heap_ops;
        recording_heap_ops.free = record_operator_delete;
        core::ptr::addr_of_mut!(MOCK_RELEASE_ONE_HANDLE).write(Some(record_release_one_handle));
        core::ptr::addr_of_mut!(crate::heap::veneers::HEAP_OPS).write_volatile(recording_heap_ops);
        *addr_of_mut!(RELEASED_ONE_HANDLE) = None;
        *addr_of_mut!(DELETED_HANDLE) = None;
        ReleaseAndDeleteReset { release, heap_ops }
    }

    #[test]
    fn release_one_handle_then_deletes_the_same_allocation() {
        let _guard = LOCK.lock();
        let mut handle = 0xfeed_c0de;
        let _reset = unsafe { record_release_and_delete() };

        unsafe {
            video_engine_release_one_handle_and_delete(
                0x1234_5678usize as *mut u8,
                &mut handle,
            );
            assert_eq!(
                RELEASED_ONE_HANDLE,
                Some((1, &mut handle as *mut u32)),
                "the r1 handle is released once; r0 is discarded"
            );
            assert_eq!(
                DELETED_HANDLE,
                Some(((&mut handle as *mut u32).cast(), 2)),
                "the unchanged r1 allocation reaches tag-2 operator_delete"
            );
        }
    }

    #[test]
    fn null_handle_still_reaches_release_but_skips_operator_delete() {
        let _guard = LOCK.lock();
        let _reset = unsafe { record_release_and_delete() };

        unsafe {
            video_engine_release_one_handle_and_delete(ptr::null_mut(), ptr::null_mut());
            assert_eq!(
                RELEASED_ONE_HANDLE,
                Some((1, ptr::null_mut())),
                "the raw body has no release-side NULL guard"
            );
            assert_eq!(
                DELETED_HANDLE,
                None,
                "operator_delete alone supplies the NULL guard"
            );
        }
    }
}
