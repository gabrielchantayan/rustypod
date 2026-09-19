//! `draw_line_engine` — original: `FUN_080e7870` @ 0x080e7870 (148 bytes,
//! 0x080e7870..0x080e7904; 2 unconditional `bl`, 0 predicated `bl`).
//!
//! Raw ARM loads the surface body's aligned +8 pixel-format word. When it is
//! 32 and `scaled` is nonzero, it left-shifts all four endpoints into 16.16
//! fixed point and calls the scaled renderer at 0x080ea434. Every other case
//! calls the integer line renderer at 0x080f2efc unchanged. Deliberate
//! deviation: both large renderers remain unported and are represented by
//! target-address seams; this port owns only the verified dispatcher.

/// ABI shared by the two retail line renderers.
pub type DrawLineRenderer = unsafe extern "C" fn(
    *const u8, i32, i32, i32, i32, i32, *const u8, i32, *const u8,
);

#[derive(Clone, Copy)]
pub struct DrawLineEngineOps {
    pub scaled_renderer: DrawLineRenderer,
    pub integer_renderer: DrawLineRenderer,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_scaled_renderer(
    surface: *const u8, x1: i32, y1: i32, x2: i32, y2: i32, thickness: i32,
    foreground: *const u8, style: i32, clip_rect: *const u8,
) {
    let renderer: DrawLineRenderer = unsafe { core::mem::transmute(0x080e_a434usize) };
    unsafe { renderer(surface, x1, y1, x2, y2, thickness, foreground, style, clip_rect) }
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_integer_renderer(
    surface: *const u8, x1: i32, y1: i32, x2: i32, y2: i32, thickness: i32,
    foreground: *const u8, style: i32, clip_rect: *const u8,
) {
    let renderer: DrawLineRenderer = unsafe { core::mem::transmute(0x080f_2efcusize) };
    unsafe { renderer(surface, x1, y1, x2, y2, thickness, foreground, style, clip_rect) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_renderer(
    _: *const u8, _: i32, _: i32, _: i32, _: i32, _: i32, _: *const u8, _: i32, _: *const u8,
) { panic!("draw_line_engine renderer is unavailable on host") }

#[cfg(target_os = "none")]
pub const DEFAULT_DRAW_LINE_ENGINE_OPS: DrawLineEngineOps = DrawLineEngineOps {
    scaled_renderer: firmware_scaled_renderer,
    integer_renderer: firmware_integer_renderer,
};
#[cfg(not(target_os = "none"))]
pub const DEFAULT_DRAW_LINE_ENGINE_OPS: DrawLineEngineOps = DrawLineEngineOps {
    scaled_renderer: missing_renderer,
    integer_renderer: missing_renderer,
};

/// Renderer implementations not yet ported from retailOS.
pub static mut DRAW_LINE_ENGINE_OPS: DrawLineEngineOps = DEFAULT_DRAW_LINE_ENGINE_OPS;

/// Selects the retailOS fixed-point or integer line renderer.
///
/// # Safety
/// `surface_body` must reference a surface body with an aligned readable word
/// at +8; all renderer arguments must be valid for the selected renderer.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn draw_line_engine(
    surface_body: *const u8, x1: i32, y1: i32, x2: i32, y2: i32, thickness: i32,
    foreground: *const u8, style: i32, clip_rect: *const u8, scaled: i32,
) {
    let pixel_format = unsafe { (surface_body.add(8) as *const i32).read() };
    let ops = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(DRAW_LINE_ENGINE_OPS)) };
    if pixel_format == 0x20 && scaled != 0 {
        unsafe { (ops.scaled_renderer)(surface_body, x1.wrapping_shl(16), y1.wrapping_shl(16), x2.wrapping_shl(16), y2.wrapping_shl(16), thickness, foreground, style, clip_rect) };
    } else {
        unsafe { (ops.integer_renderer)(surface_body, x1, y1, x2, y2, thickness, foreground, style, clip_rect) };
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: Option<(bool, [i32; 4])> = None;
    unsafe extern "C" fn scaled(_: *const u8, x1: i32, y1: i32, x2: i32, y2: i32, _: i32, _: *const u8, _: i32, _: *const u8) { unsafe { CALL = Some((true, [x1, y1, x2, y2])) } }
    unsafe extern "C" fn integer(_: *const u8, x1: i32, y1: i32, x2: i32, y2: i32, _: i32, _: *const u8, _: i32, _: *const u8) { unsafe { CALL = Some((false, [x1, y1, x2, y2])) } }
    fn run(format: i32, selector: i32) -> (bool, [i32; 4]) {
        let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut surface = [0u32; 3]; surface[2] = format as u32;
        let old = unsafe { DRAW_LINE_ENGINE_OPS };
        unsafe { CALL = None; DRAW_LINE_ENGINE_OPS = DrawLineEngineOps { scaled_renderer: scaled, integer_renderer: integer }; draw_line_engine(surface.as_ptr() as *const u8, -1, 2, i32::MAX, i32::MIN, 1, core::ptr::null(), 0, core::ptr::null(), selector); DRAW_LINE_ENGINE_OPS = old; CALL.unwrap() }
    }
    #[test]
    fn selects_integer_renderer_unless_both_scaled_conditions_hold() {
        assert_eq!(run(0x20, 0), (false, [-1, 2, i32::MAX, i32::MIN]));
        assert_eq!(run(16, 1), (false, [-1, 2, i32::MAX, i32::MIN]));
    }
    #[test]
    fn shifts_scaled_coordinates_with_arm_lsl_semantics() {
        assert_eq!(run(0x20, -7), (true, [-65536, 131072, -65536, 0]));
    }
}
