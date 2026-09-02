//! `draw_state_fill_rect_background` — original: `FUN_082643c0` @
//! 0x082643c0 (112 bytes, 0x082643c0..0x08264430; 22 `bl` call sites,
//! 0 predicated forms, 0 tail `b`, binary-scanned by decoding every
//! B/BL word in osos.dec; zero DATA words in the image hold
//! 0x082643c0, so it is never dispatched virtually). Extent confirmed
//! against the next function's entry @ 0x08264430 (its `push {lr}`),
//! with no trailing literal-pool word.
//!
//! The background-fill member of retailOS's scoped 0x44-byte
//! draw-state record (cxx/draw_state.rs): fills a record-local
//! rectangle with the record's BACKGROUND color (the +0x15 four-byte
//! color, opaque white by default — see cxx/draw_state_color.rs's
//! three-way evidence), translated by the record's origin and clipped
//! to the embedded clip rect. It is the erase-before-draw primitive:
//! 16 of the 22 call sites first set the background color through the
//! +0x15 setter FUN_08263194 (itself exactly 22 `bl` sites) and then
//! fill, e.g. the text-row repaint @ 0x0815c2b0.
//!
//! Decoded from the raw ARM at 0x082643c0:
//!
//! ```text
//! mov  r2, r0               ; this
//! push {lr}
//! ldr  r0, [r1]             ; rect.top
//! ldr  r3, [r2, #0x30]      ; origin_y
//! sub  sp, sp, #0x14
//! add  r0, r0, r3
//! str  r0, [sp, #4]         ; adjusted.top
//! ldr  r0, [r1, #4]         ; rect.left
//! ldr  r3, [r2, #0x2c]      ; origin_x
//! add  r0, r0, r3
//! str  r0, [sp, #8]         ; adjusted.left
//! ldr  r0, [r1, #8]         ; rect.bottom
//! ldr  r3, [r2, #0x30]      ; origin_y
//! add  r0, r0, r3
//! str  r0, [sp, #0xc]       ; adjusted.bottom
//! ldr  r0, [r1, #0xc]       ; rect.right
//! ldr  r1, [r2, #0x2c]      ; origin_x
//! add  r3, r2, #0x34        ; &clip rect
//! add  r0, r0, r1
//! str  r0, [sp, #0x10]      ; adjusted.right
//! ldr  r0, [r2, #0x1c]      ; surface word
//! str  r3, [sp]             ; outgoing stack arg = &clip rect
//! mov  r3, #0               ; style: solid, never the 0x22 blend path
//! add  r2, r2, #0x15        ; &background color
//! add  r1, sp, #4           ; &adjusted rect
//! add  r0, r0, #4           ; surface body = surface + 4
//! bl   0x08074898           ; the rect-fill engine (IRAM mirror)
//! pop  {r0, r1, r2, r3, ip, pc}
//! ```
//!
//! So the engine is invoked as
//!
//! ```text
//! FUN_08074898(*(this+0x1c) + 4,   // surface body
//!              &adjusted,          // rect translated by +0x2c/+0x30
//!              this + 0x15,        // background color
//!              0,                  // style: solid fill
//!              this + 0x34)        // embedded clip rect
//! ```
//!
//! The rect field mapping is QuickDraw order (ui/rect.rs: +0x0 top,
//! +0x4 left, +0x8 bottom, +0xc right), which is what fixes the
//! record's origin words: +0x30 is added to the vertical pair
//! (top/bottom) and +0x2c to the horizontal pair (left/right), exactly
//! as cxx/draw_state_line.rs's +0x30 origin_y / +0x2c origin_x. The
//! same mapping appears verbatim in the sibling @ 0x08264430 and in
//! the bitmap draw helper @ 0x08262bdc.
//!
//! The engine @ 0x08074898 (unported; lives below 0x0800aed8, so its
//! body is readable through the 0x22000000 IRAM mirror) converts the
//! color to the surface's pixel format (helper 0x08079c0c keyed on the
//! surface's +0x10 halfword), intersects the rect with the clip
//! (0x8075e90), and fills; style 0x22 with a non-0xff alpha takes a
//! per-pixel blend loop instead. This caller always passes style 0,
//! so its fills are always solid.
//!
//! Return: the epilogue `pop {r0, r1, r2, r3, ip, pc}` leaves r0 =
//! this+0x34 and r1 = adjusted.top, but every sampled call site
//! (0x0808da10, 0x0816b3cc, 0x082917d0) clobbers or reloads r0 with
//! its next instruction, so the port is void (the
//! string_id_record.rs precedent).
//!
//! Deviations: the engine @ 0x08074898 is unported, so it rides the
//! [`DRAW_STATE_FILL_OPS`] dispatch slot (the
//! checked_byte_block_forwarder.rs seam pattern, as
//! cxx/draw_state_line.rs); the target default transmutes 0x08074898,
//! the host default panics until the engine is independently ported.
//! The +0x1c surface word is read as a `u32`, not a pointer-sized
//! word: the record's layout is fixed 32-bit fields, and an 8-byte
//! host read at +0x1c would spill into the +0x20/+0x24 embedded pair
//! member. All record and rect offsets are word-aligned, so the reads
//! are plain aligned loads (the original uses `ldr`, never byte
//! assembly). No NULL guard on either pointer, matching the original's
//! unconditional `ldr`s.

use crate::ui::rect::Rect;

/// Exact fixed-width layout of the 0x44-byte draw-state record. Every
/// pointer-sized retailOS field remains a `u32`: using a host `usize`
/// here would change the following field offsets from the ARM layout.
/// Same layout as cxx/draw_state_line.rs's, with the background color
/// named (this port consumes it).
#[repr(C)]
struct DrawStateRecord {
    _current_x: i32,
    _current_y: i32,
    _flags: [u32; 2],
    _style: u8,
    _foreground: [u8; 4],
    background: [u8; 4],
    _padding_before_surface: [u8; 3],
    surface: u32,
    _embedded_pair: [u32; 2],
    _padding_after_pair: u32,
    origin_x: i32,
    origin_y: i32,
    clip_rect: [u8; 16],
}

const _: [(); 0x44] = [(); core::mem::size_of::<DrawStateRecord>()];

/// Exact ABI of the unported rect-fill engine `FUN_08074898`: surface
/// body, the origin-translated rect, the fill color, the style code
/// (0 = solid, 0x22 = alpha blend) and the clip rect.
pub type DrawStateFillEngine = unsafe extern "C" fn(
    surface_body: usize,
    rect: *const Rect,
    color: *const u8,
    style: u32,
    clip_rect: *const u8,
);

/// Calls outside this one-function port.
#[derive(Clone, Copy)]
pub struct DrawStateFillOps {
    pub fill_engine: DrawStateFillEngine,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_draw_state_fill_engine(
    surface_body: usize,
    rect: *const Rect,
    color: *const u8,
    style: u32,
    clip_rect: *const u8,
) {
    let engine: DrawStateFillEngine = core::mem::transmute(0x0807_4898usize);
    unsafe { engine(surface_body, rect, color, style, clip_rect) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_draw_state_fill_engine(
    _surface_body: usize,
    _rect: *const Rect,
    _color: *const u8,
    _style: u32,
    _clip_rect: *const u8,
) {
    panic!("draw_state_fill_rect_background requires fill engine 0x08074898")
}

#[cfg(target_os = "none")]
pub const DEFAULT_DRAW_STATE_FILL_OPS: DrawStateFillOps = DrawStateFillOps {
    fill_engine: firmware_draw_state_fill_engine,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DRAW_STATE_FILL_OPS: DrawStateFillOps = DrawStateFillOps {
    fill_engine: missing_draw_state_fill_engine,
};

/// Target builds call `FUN_08074898`; host tests replace this seam
/// with a recorder until that engine is independently ported.
pub static mut DRAW_STATE_FILL_OPS: DrawStateFillOps = DEFAULT_DRAW_STATE_FILL_OPS;

#[inline(always)]
fn draw_state_fill_ops() -> DrawStateFillOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_FILL_OPS)) }
}

/// draw_state_fill_rect_background — original: `FUN_082643c0` @
/// 0x082643c0 (112 bytes; 22 `bl` call sites, binary-scanned).
///
/// Source: `ipod-decomp/decomp/c/025/082643c0_FUN_082643c0.c` (its
/// field arithmetic matches the raw ARM; its `undefined8` return is
/// dead at every call site — see the module header).
///
/// Fills `rect` (record-local coordinates) on the record's surface
/// with the record's +0x15 background color: translates the rect by
/// the +0x2c/+0x30 origin and invokes the fill engine with the
/// surface body `*(this+0x1c) + 4`, the translated rect, the
/// background color pointer, style 0 (solid) and the embedded clip
/// rect at +0x34. Translation wraps on overflow exactly like the
/// original's `add`. Neither the record nor the caller's rect is
/// written. No NULL guard on either pointer.
///
/// # Safety
///
/// `this` must point to a valid 0x44-byte draw-state record whose
/// +0x1c surface word, +0x15 background color and +0x34 clip rect are
/// valid for the unported engine; `rect` must point to four readable
/// `i32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_fill_rect_background(this: *mut u8, rect: *const Rect) {
    let engine = draw_state_fill_ops().fill_engine;
    let state = unsafe { &*(this as *const DrawStateRecord) };
    let rect = unsafe { &*rect };
    let adjusted = Rect {
        top: rect.top.wrapping_add(state.origin_y),
        left: rect.left.wrapping_add(state.origin_x),
        bottom: rect.bottom.wrapping_add(state.origin_y),
        right: rect.right.wrapping_add(state.origin_x),
    };
    unsafe {
        engine(
            state.surface as usize + 4,
            &adjusted,
            state.background.as_ptr(),
            0,
            state.clip_rect.as_ptr(),
        );
    }
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
        rect: Rect,
        color: usize,
        style: u32,
        clip_rect: usize,
    }

    static mut SEEN: Option<EngineCall> = None;

    unsafe extern "C" fn recorder(
        surface_body: usize,
        rect: *const Rect,
        color: *const u8,
        style: u32,
        clip_rect: *const u8,
    ) {
        unsafe {
            SEEN = Some(EngineCall {
                surface_body,
                rect: *rect,
                color: color as usize,
                style,
                clip_rect: clip_rect as usize,
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
                    _current_x: -777,
                    _current_y: 555,
                    _flags: [0; 2],
                    _style: 0x2b,
                    _foreground: [0x11, 0x22, 0x33, 0x44],
                    background: [0xaa, 0xbb, 0xcc, 0xdd],
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
        let previous = unsafe { DRAW_STATE_FILL_OPS };
        unsafe {
            SEEN = None;
            DRAW_STATE_FILL_OPS = DrawStateFillOps {
                fill_engine: recorder,
            };
        }
        let result = run();
        unsafe { DRAW_STATE_FILL_OPS = previous };
        result
    }

    #[test]
    fn forwards_translated_rect_and_fixed_operands() {
        with_recorder(|| {
            let mut record = Record::new();
            let base = record.base();
            let background = record.state.background.as_ptr() as usize;
            let clip_rect = record.state.clip_rect.as_ptr() as usize;
            let rect = Rect {
                top: 3,
                left: 7,
                bottom: 42,
                right: 900,
            };
            unsafe { draw_state_fill_rect_background(base, &rect) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(
                seen,
                EngineCall {
                    surface_body: 0x0009_0004, // surface word + 4
                    rect: Rect {
                        top: -37,   // 3 + origin_y
                        left: 107,  // 7 + origin_x
                        bottom: 2,  // 42 + origin_y
                        right: 1000 // 900 + origin_x
                    },
                    color: background, // this + 0x15
                    style: 0,          // solid, never the 0x22 blend path
                    clip_rect,         // this + 0x34
                },
                "engine receives the origin-translated rect and fixed operands",
            );
        });
    }

    #[test]
    fn vertical_edges_take_origin_y_and_horizontal_take_origin_x() {
        with_recorder(|| {
            let mut record = Record::new();
            record.state.origin_x = -1;
            record.state.origin_y = 1;
            let base = record.base();
            // Every edge distinct, so a swapped origin word is visible.
            let rect = Rect {
                top: 10,
                left: 20,
                bottom: 30,
                right: 40,
            };
            unsafe { draw_state_fill_rect_background(base, &rect) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(
                seen.rect,
                Rect {
                    top: 11,
                    left: 19,
                    bottom: 31,
                    right: 39
                },
                "top/bottom move by origin_y, left/right by origin_x",
            );
        });
    }

    #[test]
    fn translation_wraps_like_arm_add() {
        with_recorder(|| {
            let mut record = Record::new();
            record.state.origin_x = i32::MAX;
            record.state.origin_y = i32::MIN;
            let base = record.base();
            let rect = Rect {
                top: -1,
                left: 1,
                bottom: 0,
                right: i32::MAX,
            };
            unsafe { draw_state_fill_rect_background(base, &rect) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(
                seen.rect,
                Rect {
                    top: i32::MAX, // MIN + (-1) wraps
                    left: i32::MIN, // MAX + 1 wraps
                    bottom: i32::MIN,
                    right: -2 // MAX + MAX wraps
                },
            );
        });
    }

    #[test]
    fn empty_rect_forwards_unchanged() {
        with_recorder(|| {
            let mut record = Record::new();
            let base = record.base();
            // The canonical empty rect (ui/rect.rs `rect_clear`): no
            // emptiness check exists here, the engine decides.
            let rect = Rect::default();
            unsafe { draw_state_fill_rect_background(base, &rect) };
            let seen = unsafe { SEEN }.expect("engine called");
            assert_eq!(
                seen.rect,
                Rect {
                    top: -40,
                    left: 100,
                    bottom: -40,
                    right: 100
                },
            );
        });
    }

    #[test]
    fn record_and_input_rect_survive_the_call() {
        with_recorder(|| {
            let mut record = Record::new();
            let before = record.state_bytes().to_vec();
            let base = record.base();
            let rect = Rect {
                top: 1,
                left: 2,
                bottom: 3,
                right: 4,
            };
            unsafe { draw_state_fill_rect_background(base, &rect) };
            assert!(record.guards_intact(), "bytes past the record are untouched");
            assert_eq!(
                record.state_bytes(),
                &before[..],
                "the original writes only its stack frame, never the record",
            );
            assert_eq!(
                rect,
                Rect {
                    top: 1,
                    left: 2,
                    bottom: 3,
                    right: 4
                },
                "the caller's rect is translated on the stack, not in place",
            );
        });
    }
}
