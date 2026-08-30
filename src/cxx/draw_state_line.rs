//! `draw_state_line` — original: `FUN_0826412c` @ 0x0826412c (120 bytes,
//! 0x0826412c..0x082641a4; 39 `bl` call sites, 0 `b`, 0 predicated,
//! binary-scanned by decoding every B/BL word in osos.dec).
//!
//! The line-drawing member of retailOS's scoped 0x44-byte draw-state
//! record (cxx/draw_state.rs): draws a one-pixel-wide foreground line
//! between two record-local points and makes the second point the
//! record's current point. The sibling @ 0x082641a4 (112 bytes,
//! unported) is the same shape with the CURRENT point as the start —
//! a `line_to`; this function takes both endpoints explicitly.
//!
//! Decoded from the raw ARM at 0x0826412c:
//!
//! ```text
//! push {r4, r5, r6, r7, lr}
//! mov  r4, r0               ; this
//! ldr  r0, [r0, #0x1c]      ; surface word
//! sub  sp, sp, #0x1c
//! mov  lr, r1               ; x1
//! ldrb r1, [r4, #0x10]      ; style byte
//! mov  r7, r2               ; y1
//! mov  r5, r3               ; x2
//! add  ip, r0, #4           ; surface body = surface + 4
//! ldr  r6, [sp, #0x30]      ; y2 (the fifth, stack-carried argument)
//! add  r0, r4, #0x11        ; &foreground color
//! mov  r3, #0
//! add  r2, r4, #0x34        ; &clip rect
//! str  r2, [sp, #0x10]
//! str  r3, [sp, #0x14]      ; outgoing stack word 5 = 0 (no scaling)
//! str  r0, [sp, #8]
//! str  r1, [sp, #0xc]
//! ldr  r0, [r4, #0x30]      ; origin_y
//! mov  r3, #1               ; thickness
//! add  r2, r0, r6
//! strd r2, [sp]             ; outgoing stack words 0/1 = y2', 1
//! ldr  r1, [r4, #0x2c]      ; origin_x
//! add  r2, r0, r7           ; y1' = origin_y + y1
//! add  r3, r1, r5           ; x2' = origin_x + x2
//! add  r1, r1, lr           ; x1' = origin_x + x1
//! mov  r0, ip
//! bl   0x080e7870           ; the line-draw engine dispatcher
//! stm  r4, {r5, r6}         ; current point = (x2, y2) — AFTER the call
//! add  sp, sp, #0x1c
//! pop  {r4, r5, r6, r7, pc}
//! ```
//!
//! So the engine is invoked as
//!
//! ```text
//! FUN_080e7870(*(this+0x1c) + 4,            // surface body
//!              origin_x + x1, origin_y + y1,
//!              origin_x + x2, origin_y + y2,
//!              1,                           // line thickness
//!              this + 0x11,                 // foreground color
//!              style byte at +0x10,
//!              this + 0x34,                 // embedded clip rect
//!              0)                           // never the 16.16 scaled path
//! ```
//!
//! The engine @ 0x080e7870 (148 bytes, unported) dispatches on the
//! surface's +8 pixel-format word and its tenth argument: 32 bpp AND a
//! nonzero tenth argument take the 16.16 fixed-point variant
//! 0x080ea434, everything else the integer Bresenham engine
//! 0x080f2efc (endpoint-normalizing, degenerate-point fill path via
//! 0x08074898). This caller always passes 0, so its lines always take
//! the integer engine. Endpoint arithmetic is plain 32-bit wrapping
//! `add`; callers pass negative locals freely (e.g. 0x081c97c4 passes
//! `param_3[2] - 6`). Call-site evidence for "line": 0x0826343c draws
//! a rectangle outline as four calls sharing endpoints, switching
//! colors between the pairs through color_copy @ 0x082720e8.
//!
//! The record fields consumed here match the layout cxx/draw_state.rs
//! establishes from the constructor and the draw-setup routines:
//! current point +0x00/+0x04 (body_init zeroes both), style byte
//! +0x10, foreground color +0x11..+0x14, surface +0x1c, origin
//! +0x2c/+0x30, embedded clip rect +0x34..+0x43.
//!
//! Deviations: the engine @ 0x080e7870 is unported, so it rides the
//! [`DRAW_STATE_LINE_OPS`] dispatch slot (the
//! checked_byte_block_forwarder.rs seam pattern); the target default
//! transmutes 0x080e7870, the host default panics until the engine is
//! independently ported. The +0x1c surface word is read as a `u32`,
//! not a pointer-sized word: the record's layout is fixed 32-bit
//! fields, and an 8-byte host read at +0x1c would spill into the
//! +0x20/+0x24 embedded pair member. All record offsets are
//! word-aligned, so the reads are plain aligned loads (the original
//! uses `ldr`/`ldrb`, never byte assembly). The current-point store
//! intentionally happens after the engine returns, matching the
//! original's post-`bl` `stm r4, {r5, r6}` — an engine that inspects
//! the record mid-draw sees the OLD current point. No NULL guard on
//! `this`, matching the original.

/// Exact fixed-width layout of the 0x44-byte draw-state record. Every
/// pointer-sized retailOS field remains a `u32`: using a host `usize` here
/// would change the following field offsets from the ARM layout.
#[repr(C)]
struct DrawStateRecord {
    current_x: i32,
    current_y: i32,
    _flags: [u32; 2],
    style: u8,
    foreground: [u8; 4],
    _background: [u8; 4],
    _padding_before_surface: [u8; 3],
    surface: u32,
    _embedded_pair: [u32; 2],
    _padding_after_pair: u32,
    origin_x: i32,
    origin_y: i32,
    clip_rect: [u8; 16],
}

const _: [(); 0x44] = [(); core::mem::size_of::<DrawStateRecord>()];

/// Exact ABI of the unported line-draw engine dispatcher `FUN_080e7870`:
/// surface body, the four translated endpoint coordinates, line
/// thickness, foreground color pointer, style byte, clip rect pointer,
/// and the scaled-path selector.
pub type DrawStateLineEngine = unsafe extern "C" fn(
    surface_body: usize,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    thickness: i32,
    foreground: *const u8,
    style: u8,
    clip_rect: *const u8,
    scaled: i32,
);

/// Calls outside this one-function port.
#[derive(Clone, Copy)]
pub struct DrawStateLineOps {
    pub line_engine: DrawStateLineEngine,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_draw_state_line_engine(
    surface_body: usize,
    x1: i32,
    y1: i32,
    x2: i32,
    y2: i32,
    thickness: i32,
    foreground: *const u8,
    style: u8,
    clip_rect: *const u8,
    scaled: i32,
) {
    let engine: DrawStateLineEngine = core::mem::transmute(0x080e_7870usize);
    unsafe {
        engine(
            surface_body,
            x1,
            y1,
            x2,
            y2,
            thickness,
            foreground,
            style,
            clip_rect,
            scaled,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_draw_state_line_engine(
    _surface_body: usize,
    _x1: i32,
    _y1: i32,
    _x2: i32,
    _y2: i32,
    _thickness: i32,
    _foreground: *const u8,
    _style: u8,
    _clip_rect: *const u8,
    _scaled: i32,
) {
    panic!("draw_state_line requires line engine 0x080e7870")
}

#[cfg(target_os = "none")]
pub const DEFAULT_DRAW_STATE_LINE_OPS: DrawStateLineOps = DrawStateLineOps {
    line_engine: firmware_draw_state_line_engine,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DRAW_STATE_LINE_OPS: DrawStateLineOps = DrawStateLineOps {
    line_engine: missing_draw_state_line_engine,
};

/// Target builds call `FUN_080e7870`; host tests replace this seam with
/// a recorder until that engine is independently ported.
pub static mut DRAW_STATE_LINE_OPS: DrawStateLineOps = DEFAULT_DRAW_STATE_LINE_OPS;

#[inline(always)]
fn draw_state_line_ops() -> DrawStateLineOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_LINE_OPS)) }
}

/// draw_state_line — original: `FUN_0826412c` @ 0x0826412c (120 bytes;
/// 39 `bl` call sites, binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/025/0826412c_FUN_0826412c.c`
/// (argument order verified against the raw ARM; Ghidra's C is right
/// here).
///
/// Draws a one-pixel foreground line on the record's surface from
/// record-local `(x1, y1)` to `(x2, y2)`, both translated by the
/// record's +0x2c/+0x30 origin, clipped to the embedded rect at +0x34,
/// then sets the record's current point to `(x2, y2)` after the engine
/// returns. Endpoint translation wraps on overflow exactly like the
/// original's `add`. No NULL guard on `this`.
///
/// # Safety
///
/// `this` must point to a valid 0x44-byte draw-state record whose
/// +0x1c surface word, +0x11 foreground color and +0x34 clip rect are
/// valid for the unported engine.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_line(this: *mut u8, x1: i32, y1: i32, x2: i32, y2: i32) {
    let engine = draw_state_line_ops().line_engine;
    let state = unsafe { &mut *(this as *mut DrawStateRecord) };
    unsafe {
        engine(
            state.surface as usize + 4,
            state.origin_x.wrapping_add(x1),
            state.origin_y.wrapping_add(y1),
            state.origin_x.wrapping_add(x2),
            state.origin_y.wrapping_add(y2),
            1,
            state.foreground.as_ptr(),
            state.style,
            state.clip_rect.as_ptr(),
            0,
        );
    }
    state.current_x = x2;
    state.current_y = y2;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    const GUARD: u8 = 0xa5;

    #[derive(Clone, Copy, PartialEq, Debug)]
    struct EngineCall {
        surface_body: usize,
        x1: i32,
        y1: i32,
        x2: i32,
        y2: i32,
        thickness: i32,
        foreground: usize,
        style: u8,
        clip_rect: usize,
        scaled: i32,
        point_during_call: (i32, i32),
    }

    static mut SEEN: Option<EngineCall> = None;

    unsafe extern "C" fn recorder(
        surface_body: usize,
        x1: i32,
        y1: i32,
        x2: i32,
        y2: i32,
        thickness: i32,
        foreground: *const u8,
        style: u8,
        clip_rect: *const u8,
        scaled: i32,
    ) {
        // The record base is recoverable from its named foreground field;
        // capture its current point before the caller's post-call stores.
        let state = unsafe {
            foreground
                .sub(core::mem::offset_of!(DrawStateRecord, foreground))
                as *const DrawStateRecord
        };
        let point_during_call = unsafe { ((*state).current_x, (*state).current_y) };
        unsafe {
            SEEN = Some(EngineCall {
                surface_body,
                x1,
                y1,
                x2,
                y2,
                thickness,
                foreground: foreground as usize,
                style,
                clip_rect: clip_rect as usize,
                scaled,
                point_during_call,
            });
        }
    }

    #[repr(C)]
    struct Record {
        state: DrawStateRecord,
        guard: [u8; 8],
    }

    impl Record {
        fn new() -> Self {
            Record {
                state: DrawStateRecord {
                    current_x: -777,
                    current_y: 555,
                    _flags: [0; 2],
                    style: 0x2b,
                    foreground: [0x11, 0x22, 0x33, 0x44],
                    _background: [0xff; 4],
                    _padding_before_surface: [0; 3],
                    surface: 0x0009_0000,
                    _embedded_pair: [0; 2],
                    _padding_after_pair: 0,
                    origin_x: 100,
                    origin_y: -40,
                    clip_rect: [0x5c; 16],
                },
                guard: [GUARD; 8],
            }
        }

        fn base(&mut self) -> *mut u8 {
            &mut self.state as *mut DrawStateRecord as *mut u8
        }

        fn state_bytes(&self) -> &[u8] {
            unsafe {
                core::slice::from_raw_parts(
                    &self.state as *const DrawStateRecord as *const u8,
                    core::mem::size_of::<DrawStateRecord>(),
                )
            }
        }

        fn guards_intact(&self) -> bool {
            self.guard.iter().all(|&byte| byte == GUARD)
        }
    }

    fn with_recorder<T>(run: impl FnOnce() -> T) -> T {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let previous = unsafe { DRAW_STATE_LINE_OPS };
        unsafe {
            SEEN = None;
            DRAW_STATE_LINE_OPS = DrawStateLineOps {
                line_engine: recorder,
            };
        }
        let result = run();
        unsafe { DRAW_STATE_LINE_OPS = previous };
        result
    }

    #[test]
    fn forwards_translated_endpoints_and_fixed_operands() {
        with_recorder(|| {
            let mut record = Record::new();
            let base = record.base();
            let foreground = record.state.foreground.as_ptr() as usize;
            let clip_rect = record.state.clip_rect.as_ptr() as usize;
            unsafe { draw_state_line(base, 3, 7, 42, 900) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(
                seen,
                EngineCall {
                    surface_body: 0x0009_0004, // surface word + 4
                    x1: 103,
                    y1: -33,
                    x2: 142,
                    y2: 860,
                    thickness: 1,
                    foreground,
                    style: 0x2b,
                    clip_rect,
                    scaled: 0,
                    point_during_call: (-777, 555), // old point visible mid-draw
                },
                "engine receives origin-translated endpoints and fixed operands",
            );
        });
    }

    #[test]
    fn current_point_updates_to_second_endpoint_after_the_call() {
        with_recorder(|| {
            let mut record = Record::new();
            let base = record.base();
            unsafe { draw_state_line(base, 1, 2, -9, i32::MAX) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(seen.point_during_call, (-777, 555));
            assert_eq!((record.state.current_x, record.state.current_y), (-9, i32::MAX));
        });
    }

    #[test]
    fn endpoint_translation_wraps_like_arm_add() {
        with_recorder(|| {
            let mut record = Record::new();
            record.state.origin_x = i32::MAX;
            record.state.origin_y = i32::MIN;
            let base = record.base();
            unsafe { draw_state_line(base, 1, -1, i32::MAX, 0) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(seen.x1, i32::MIN); // MAX + 1 wraps
            assert_eq!(seen.y1, i32::MAX); // MIN + (-1) wraps
            assert_eq!(seen.x2, -2); // MAX + MAX wraps
            assert_eq!(seen.y2, i32::MIN);
        });
    }

    #[test]
    fn degenerate_line_forwards_unchanged() {
        with_recorder(|| {
            let mut record = Record::new();
            let base = record.base();
            unsafe { draw_state_line(base, 5, 5, 5, 5) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!((seen.x1, seen.y1), (105, -35));
            assert_eq!((seen.x2, seen.y2), (105, -35));
            assert_eq!((record.state.current_x, record.state.current_y), (5, 5));
        });
    }

    #[test]
    fn record_bytes_outside_the_current_point_survive() {
        with_recorder(|| {
            let mut record = Record::new();
            let before = record.state_bytes().to_vec();
            let base = record.base();
            unsafe { draw_state_line(base, 0, 0, 1, 1) };
            assert!(record.guards_intact(), "bytes past the record are untouched");
            assert_eq!(
                &record.state_bytes()[8..],
                &before[8..],
                "only the two current-point words may change",
            );
            assert_eq!(record.state.foreground, [0x11, 0x22, 0x33, 0x44]);
            assert_eq!(record.state.style, 0x2b);
        });
    }
}
