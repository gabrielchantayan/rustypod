//! `draw_state_stroke_rect` — original: `FUN_08264430` @ 0x08264430
//! (120 bytes, 0x08264430..0x082644a8; 8 unconditional `bl` call sites,
//! no predicated forms and no tail `b`, binary-scanned by decoding every
//! ARM B/BL word in osos.dec). The next distinct sibling begins at
//! 0x082644a8 (`mov r2,r0; push {lr}`); no literal pool follows, and no
//! DATA word in the image holds 0x08264430, so this is not virtual dispatch.
//!
//! This member of the scoped 0x44-byte draw-state record strokes a
//! record-local QuickDraw rect: it translates top/bottom by origin_y at
//! +0x30 and left/right by origin_x at +0x2c, then calls the unported
//! rectangle-outline engine 0x08074788. Raw ARM passes surface body
//! `*(this+0x1c)+4`, the translated rect, the signed width word at +0x08,
//! foreground colour this+0x11, zero-extended style byte this+0x10, and
//! embedded clip rect this+0x34. The engine's decompilation constructs four
//! filled edge rectangles, consistent with this being the stroke primitive.
//!
//! Decoded from raw ARM at 0x08264430:
//!
//! ```text
//! push {lr}
//! ldr/add/str rect.top,    [this,#0x30], [sp,#0xc]
//! ldr/add/str rect.left,   [this,#0x2c], [sp,#0x10]
//! ldr/add/str rect.bottom, [this,#0x30], [sp,#0x14]
//! ldr/add/str rect.right,  [this,#0x2c], [sp,#0x18]
//! ldrb r2,[this,#0x10]                 ; style, zero extended
//! ldr  r1,[this,#0x1c]                 ; surface word
//! strd r2,r3,[sp]                      ; style, this+0x34 clip
//! add  ip,r1,#4                        ; surface body
//! ldr  r2,[this,#8]                    ; stroke width
//! add  r3,this,#0x11                   ; foreground colour
//! mov  r0,ip; add r1,sp,#0xc
//! bl   0x08074788
//! ```
//!
//! Deliberate deviation: the outline engine is unported, so this module's
//! volatile dispatch slot reaches its firmware address on target builds and
//! lets host tests install a recorder. The fixed-width surface is read as a
//! `u32`, and its `+4` wraps at 32 bits before becoming a host `usize`.
//! There is no NULL guard on either input, matching the original.

use crate::ui::rect::Rect;

/// Exact fixed-width layout of the 0x44-byte draw-state record. Pointer
/// fields remain `u32` so the following fields retain their ARM offsets on a
/// 64-bit host.
#[repr(C)]
struct DrawStateRecord {
    _current_x: i32,
    _current_y: i32,
    stroke_width: i32,
    _flags: u32,
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

/// Exact ABI of the unported rectangle-outline engine `FUN_08074788`.
pub type DrawStateStrokeEngine = unsafe extern "C" fn(
    surface_body: usize,
    rect: *const Rect,
    stroke_width: i32,
    foreground: *const u8,
    style: u8,
    clip_rect: *const u8,
);

/// Calls outside this one-function port.
#[derive(Clone, Copy)]
pub struct DrawStateStrokeOps {
    pub stroke_engine: DrawStateStrokeEngine,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_draw_state_stroke_engine(
    surface_body: usize,
    rect: *const Rect,
    stroke_width: i32,
    foreground: *const u8,
    style: u8,
    clip_rect: *const u8,
) {
    let engine: DrawStateStrokeEngine = core::mem::transmute(0x0807_4788usize);
    unsafe { engine(surface_body, rect, stroke_width, foreground, style, clip_rect) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_draw_state_stroke_engine(
    _surface_body: usize,
    _rect: *const Rect,
    _stroke_width: i32,
    _foreground: *const u8,
    _style: u8,
    _clip_rect: *const u8,
) {
    panic!("draw_state_stroke_rect requires stroke engine 0x08074788")
}

#[cfg(target_os = "none")]
pub const DEFAULT_DRAW_STATE_STROKE_OPS: DrawStateStrokeOps = DrawStateStrokeOps {
    stroke_engine: firmware_draw_state_stroke_engine,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DRAW_STATE_STROKE_OPS: DrawStateStrokeOps = DrawStateStrokeOps {
    stroke_engine: missing_draw_state_stroke_engine,
};

/// Target builds call `FUN_08074788`; host tests replace this seam with a
/// recorder until that engine is independently ported.
pub static mut DRAW_STATE_STROKE_OPS: DrawStateStrokeOps = DEFAULT_DRAW_STATE_STROKE_OPS;

#[inline(always)]
fn draw_state_stroke_ops() -> DrawStateStrokeOps {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DRAW_STATE_STROKE_OPS)) }
}

/// draw_state_stroke_rect — original: `FUN_08264430` @ 0x08264430 (120
/// bytes; 8 `bl` call sites, binary-scanned).
///
/// Translates `rect` from record-local coordinates and strokes its outline
/// with the record's +0x08 width, +0x11 foreground colour, +0x10 style and
/// +0x34 clip rect. Translation and surface-body addition have native ARM
/// 32-bit wrapping semantics. Neither input is written.
///
/// # Safety
///
/// `this` must point to a valid 0x44-byte draw-state record whose +0x1c
/// surface word, +0x11 foreground colour and +0x34 clip rect are valid for
/// the unported engine; `rect` must point to four readable `i32` words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_state_stroke_rect(this: *mut u8, rect: *const Rect) {
    let engine = draw_state_stroke_ops().stroke_engine;
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
            state.surface.wrapping_add(4) as usize,
            &adjusted,
            state.stroke_width,
            state.foreground.as_ptr(),
            state.style,
            state.clip_rect.as_ptr(),
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    const GUARD: u8 = 0xa5;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct EngineCall {
        surface_body: usize,
        rect: Rect,
        stroke_width: i32,
        foreground: usize,
        style: u8,
        clip_rect: usize,
    }

    static mut SEEN: Option<EngineCall> = None;

    unsafe extern "C" fn recorder(
        surface_body: usize,
        rect: *const Rect,
        stroke_width: i32,
        foreground: *const u8,
        style: u8,
        clip_rect: *const u8,
    ) {
        unsafe {
            SEEN = Some(EngineCall {
                surface_body,
                rect: *rect,
                stroke_width,
                foreground: foreground as usize,
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
            Self {
                state: DrawStateRecord {
                    _current_x: -777,
                    _current_y: 555,
                    stroke_width: 3,
                    _flags: 0x1234_5678,
                    style: 0x22,
                    foreground: [0x11, 0x22, 0x33, 0x44],
                    _background: [0xaa, 0xbb, 0xcc, 0xdd],
                    _padding_before_surface: [0; 3],
                    surface: 0x0009_0000,
                    _embedded_pair: [0xdead_beef, 0x0123_4567],
                    _padding_after_pair: 0x89ab_cdef,
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

        fn bytes(&self) -> &[u8] {
            unsafe {
                core::slice::from_raw_parts(
                    &self.state as *const DrawStateRecord as *const u8,
                    core::mem::size_of::<DrawStateRecord>(),
                )
            }
        }
    }

    unsafe fn install_recorder() -> DrawStateStrokeOps {
        let previous = unsafe { DRAW_STATE_STROKE_OPS };
        unsafe {
            DRAW_STATE_STROKE_OPS = DrawStateStrokeOps {
                stroke_engine: recorder,
            };
            SEEN = None;
        }
        previous
    }

    unsafe fn restore_ops(previous: DrawStateStrokeOps) {
        unsafe { DRAW_STATE_STROKE_OPS = previous }
    }

    #[test]
    fn forwards_all_operands_and_preserves_inputs() {
        let _guard = OPS_LOCK.lock();
        let previous = unsafe { install_recorder() };
        let mut record = Record::new();
        let rect = Rect { top: 7, left: -9, bottom: 31, right: 44 };
        let state_before = record.bytes().to_vec();

        unsafe { draw_state_stroke_rect(record.base(), &rect) };

        let seen = unsafe { SEEN.unwrap() };
        assert_eq!(seen.surface_body, 0x0009_0004);
        assert_eq!(seen.rect, Rect { top: -33, left: 91, bottom: -9, right: 144 });
        assert_eq!(seen.stroke_width, 3);
        assert_eq!(seen.foreground, record.state.foreground.as_ptr() as usize);
        assert_eq!(seen.style, 0x22);
        assert_eq!(seen.clip_rect, record.state.clip_rect.as_ptr() as usize);
        assert_eq!(record.bytes(), state_before.as_slice());
        assert!(record.guard.iter().all(|&byte| byte == GUARD));
        assert_eq!(rect, Rect { top: 7, left: -9, bottom: 31, right: 44 });

        unsafe { restore_ops(previous) };
    }

    #[test]
    fn wraps_coordinates_and_surface_at_arm_word_width() {
        let _guard = OPS_LOCK.lock();
        let previous = unsafe { install_recorder() };
        let mut record = Record::new();
        record.state.surface = u32::MAX;
        record.state.stroke_width = i32::MIN;
        record.state.style = 0xff;
        record.state.origin_x = 1;
        record.state.origin_y = -1;
        let rect = Rect {
            top: i32::MIN,
            left: i32::MAX,
            bottom: i32::MAX,
            right: i32::MIN,
        };

        unsafe { draw_state_stroke_rect(record.base(), &rect) };

        let seen = unsafe { SEEN.unwrap() };
        assert_eq!(seen.surface_body, 3);
        assert_eq!(seen.rect, Rect { top: i32::MAX, left: i32::MIN, bottom: i32::MAX - 1, right: i32::MIN + 1 });
        assert_eq!(seen.stroke_width, i32::MIN);
        assert_eq!(seen.style, 0xff);

        unsafe { restore_ops(previous) };
    }

    #[test]
    fn forwards_degenerate_rect_without_local_rejection() {
        let _guard = OPS_LOCK.lock();
        let previous = unsafe { install_recorder() };
        let mut record = Record::new();
        record.state.origin_x = -7;
        record.state.origin_y = 9;
        let rect = Rect { top: 20, left: 30, bottom: 20, right: 30 };

        unsafe { draw_state_stroke_rect(record.base(), &rect) };

        let seen = unsafe { SEEN.unwrap() };
        assert_eq!(seen.rect, Rect { top: 29, left: 23, bottom: 29, right: 23 });

        unsafe { restore_ops(previous) };
    }
}
