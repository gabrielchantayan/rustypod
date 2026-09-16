//! FreeType strike-metric selection (`FT_Select_Metrics` from ftobjs.c).

use core::ffi::c_void;

use crate::ft::calc::ft_divfix;
use crate::ft::glyph_slot::FtFace;

/// FreeType `FT_Bitmap_Size` — a 16-byte strike descriptor on the retail
/// ARM ABI: `height`/`width` are signed shorts, then three 32-bit fields.
#[repr(C)]
pub struct FtBitmapSize {
    pub height: i16,
    pub width: i16,
    pub size: i32,
    pub x_ppem: i32,
    pub y_ppem: i32,
}

/// FreeType `FT_Size_Metrics` — the retail 32-byte block at `size + 0x0c`.
#[repr(C)]
pub struct FtSizeMetrics {
    pub x_ppem: u16,
    pub y_ppem: u16,
    pub x_scale: i32,
    pub y_scale: i32,
    pub ascender: i32,
    pub descender: i32,
    pub height: i32,
    pub max_advance: i32,
}

/// `FT_SizeRec` prefix through `metrics`: three word-sized pointers
/// (`face`, `driver`, `memory`) followed by the 32-byte metrics block at
/// +0x0c on ARM.
#[repr(C)]
pub struct FtSizeRec {
    pub face: *mut FtFace,
    pub driver: *mut c_void,
    pub memory: *mut c_void,
    pub metrics: FtSizeMetrics,
}

/// ABI of the unported scalable-metrics finalize helper at `0x080db840`.
///
/// The retail body splits `FT_Request_Metrics`'s ascender/descender/height/
/// max_advance computation into a shared subroutine (also tail-called from
/// `0x0804e960`): it multiplies the face's `ascender`/`descender`/`height`
/// shorts by `metrics->y_scale` via `ft_mulfix`, ceiling `ascender` to 64
/// and rounding `height`, then derives `max_advance` from `x_scale`.
pub type FtMetricsScalableFinalizeFn =
    unsafe extern "C" fn(face: *mut FtFace, metrics: *mut FtSizeMetrics);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_metrics_scalable_finalize(
    face: *mut FtFace,
    metrics: *mut FtSizeMetrics,
) {
    let finalize: FtMetricsScalableFinalizeFn = core::mem::transmute(0x080db840usize);
    finalize(face, metrics)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn firmware_metrics_scalable_finalize(
    _face: *mut FtFace,
    _metrics: *mut FtSizeMetrics,
) {
    panic!("ft_select_metrics requires scalable finalize helper 0x080db840")
}

/// Host-replaceable scalable-finalize call. `0x080db840` is absent from
/// `names.yaml`; target builds dispatch to that verified retailOS address.
pub static mut METRICS_SCALABLE_FINALIZE: FtMetricsScalableFinalizeFn =
    firmware_metrics_scalable_finalize;

#[inline(always)]
unsafe fn metrics_scalable_finalize() -> FtMetricsScalableFinalizeFn {
    core::ptr::read_volatile(core::ptr::addr_of!(METRICS_SCALABLE_FINALIZE))
}

/// ft_select_metrics (FreeType 2.3 `FT_Select_Metrics`, ftobjs.c) —
/// original: `FUN_0804eafc` at load address 0x0804eafc, 176 bytes
/// (0x0804eafc..0x0804ebac; the next distinct function starts at
/// 0x0804ebac, confirmed by raw osos.dec decode).
///
/// A complete ARM B/BL scan finds five direct callers, all unconditional
/// `bl` at 0x0803d178, 0x0804ebf4, 0x0808cb94, 0x0808da88, and 0x08090454;
/// no predicated inbound calls. The body contains two `bl` instructions,
/// both to `ft_divfix` @ 0x0804c2d4, plus one tail `b` to the shared
/// scalable-metrics finalize helper at 0x080db840 (unported; modeled as a
/// dispatch seam — see [`METRICS_SCALABLE_FINALIZE`]).
///
/// Algorithm: fetch `face->size`'s metrics block and the `strike_index`th
/// 16-byte `FT_Bitmap_Size` from `face->available_sizes`. Store
/// `x_ppem`/`y_ppem` as the strike's 26.6 ppem values rounded to integers
/// via the retail shift pair `(ppem + 0x20) << 10 >> 16` (wrapping 32-bit,
/// truncated to u16; for in-range ppem this is `(ppem + 32) >> 6`). For a
/// scalable face (`face_flags & 1`) compute `x_scale`/`y_scale` as
/// `ft_divfix(strike_ppem, units_per_em)` and tail-call the finalize
/// helper. For a bitmap-only face store `x_scale = y_scale = 0x400000`
/// (64.0 in 16.16), `ascender = bsize->y_ppem`, `descender = 0`,
/// `height = bsize->height << 6` (sign-extended), and
/// `max_advance = bsize->x_ppem`.
///
/// Deliberate deviations: Ghidra's decompilation fuses the rounding shift
/// pair into `* 0x400 >> 0x10` (same semantics) and shows the tail
/// helper's body inlined; the raw listing is authoritative. The `lsl #4`
/// strike index scaling is preserved exactly.
///
/// # Safety
///
/// `face` must be a valid retail `FT_FaceRec` with a non-null `size` and,
/// for `strike_index`, a valid `available_sizes` array with at least
/// `strike_index + 1` entries. The retail routine has no null guards.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_select_metrics(face: *mut FtFace, strike_index: u32) {
    let face = &mut *face;
    let size = &mut *face.size.cast::<FtSizeRec>();
    let metrics = &mut size.metrics;
    let bsize = &*face.available_sizes.cast::<FtBitmapSize>().add(strike_index as usize);

    metrics.x_ppem = ((bsize.x_ppem.wrapping_add(0x20).wrapping_shl(10) as u32) >> 16) as u16;
    metrics.y_ppem = ((bsize.y_ppem.wrapping_add(0x20).wrapping_shl(10) as u32) >> 16) as u16;

    if face.face_flags & 1 != 0 {
        metrics.x_scale = ft_divfix(bsize.x_ppem, face.units_per_em as i32);
        metrics.y_scale = ft_divfix(bsize.y_ppem, face.units_per_em as i32);
        metrics_scalable_finalize()(face, metrics);
        return;
    }

    metrics.x_scale = 0x400000;
    metrics.y_scale = 0x400000;
    metrics.ascender = bsize.y_ppem;
    metrics.descender = 0;
    metrics.height = (bsize.height as i32) << 6;
    metrics.max_advance = bsize.x_ppem;
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        ft_select_metrics, FtBitmapSize, FtFace, FtMetricsScalableFinalizeFn, FtSizeMetrics,
        FtSizeRec, METRICS_SCALABLE_FINALIZE,
    };
    use crate::ft::calc::ft_divfix;
    use core::ffi::c_void;
    use core::ptr;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    static FINALIZE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FINALIZE_FACE: AtomicUsize = AtomicUsize::new(0);
    static FINALIZE_METRICS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn fake_finalize(face: *mut FtFace, metrics: *mut FtSizeMetrics) {
        FINALIZE_CALLS.fetch_add(1, Ordering::SeqCst);
        FINALIZE_FACE.store(face as usize, Ordering::SeqCst);
        FINALIZE_METRICS.store(metrics as usize, Ordering::SeqCst);
        (*metrics).ascender = 0x1111_2222;
        (*metrics).descender = -0x3333;
        (*metrics).height = 0x4444;
        (*metrics).max_advance = 0x5555;
    }

    fn bitmap_size(height: i16, x_ppem: i32, y_ppem: i32) -> FtBitmapSize {
        FtBitmapSize { height, width: 0, size: 0, x_ppem, y_ppem }
    }

    fn zero_metrics() -> FtSizeMetrics {
        FtSizeMetrics {
            x_ppem: 0,
            y_ppem: 0,
            x_scale: 0,
            y_scale: 0,
            ascender: 0,
            descender: 0,
            height: 0,
            max_advance: 0,
        }
    }

    fn face_with(face_flags: i32, sizes: *mut c_void, size: *mut FtSizeRec) -> FtFace {
        FtFace {
            num_faces: 0,
            face_index: 0,
            face_flags,
            style_flags: 0,
            num_glyphs: 0,
            family_name: ptr::null_mut(),
            style_name: ptr::null_mut(),
            num_fixed_sizes: 0,
            available_sizes: sizes,
            num_charmaps: 0,
            charmaps: ptr::null_mut(),
            generic: crate::ft::glyph_slot::FtGeneric {
                data: ptr::null_mut(),
                finalizer: None,
            },
            bbox: crate::ft::types::FtBBox { x_min: 0, y_min: 0, x_max: 0, y_max: 0 },
            units_per_em: 1000,
            ascender: 0,
            descender: 0,
            height: 0,
            max_advance_width: 0,
            max_advance_height: 0,
            underline_position: 0,
            underline_thickness: 0,
            glyph: ptr::null_mut(),
            size: size.cast::<c_void>(),
            charmap: ptr::null_mut(),
            driver: ptr::null_mut(),
            memory: ptr::null_mut(),
        }
    }

    #[test]
    fn bitmap_face_writes_integer_metrics_without_finalize() {
        let _guard = TEST_LOCK.lock();
        FINALIZE_CALLS.store(0, Ordering::SeqCst);

        let mut strikes = [bitmap_size(-13, 12 << 6, 11 << 6), bitmap_size(0, 0, 0)];
        let mut size = FtSizeRec {
            face: ptr::null_mut(),
            driver: ptr::null_mut(),
            memory: ptr::null_mut(),
            metrics: zero_metrics(),
        };
        let mut face = face_with(0, strikes.as_mut_ptr().cast(), &mut size);

        unsafe { ft_select_metrics(&mut face, 0) };

        assert_eq!(size.metrics.x_ppem, 12);
        assert_eq!(size.metrics.y_ppem, 11);
        assert_eq!(size.metrics.x_scale, 0x400000);
        assert_eq!(size.metrics.y_scale, 0x400000);
        assert_eq!(size.metrics.ascender, 11 << 6);
        assert_eq!(size.metrics.descender, 0);
        assert_eq!(size.metrics.height, -13 << 6);
        assert_eq!(size.metrics.max_advance, 12 << 6);
        assert_eq!(FINALIZE_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn scalable_face_divfixes_scales_and_tail_calls_finalize() {
        let _guard = TEST_LOCK.lock();
        let saved: FtMetricsScalableFinalizeFn = unsafe { METRICS_SCALABLE_FINALIZE };
        unsafe { METRICS_SCALABLE_FINALIZE = fake_finalize };
        FINALIZE_CALLS.store(0, Ordering::SeqCst);

        let mut strikes = [bitmap_size(0, 0, 0), bitmap_size(0, 16 << 6, 12 << 6)];
        let mut size = FtSizeRec {
            face: ptr::null_mut(),
            driver: ptr::null_mut(),
            memory: ptr::null_mut(),
            metrics: zero_metrics(),
        };
        let mut face = face_with(1, strikes.as_mut_ptr().cast(), &mut size);

        unsafe { ft_select_metrics(&mut face, 1) };

        assert_eq!(size.metrics.x_ppem, 16);
        assert_eq!(size.metrics.y_ppem, 12);
        assert_eq!(size.metrics.x_scale, ft_divfix(16 << 6, 1000));
        assert_eq!(size.metrics.y_scale, ft_divfix(12 << 6, 1000));
        assert_eq!(FINALIZE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FINALIZE_FACE.load(Ordering::SeqCst), &mut face as *mut _ as usize);
        assert_eq!(
            FINALIZE_METRICS.load(Ordering::SeqCst),
            &mut size.metrics as *mut _ as usize
        );
        assert_eq!(size.metrics.ascender, 0x1111_2222);
        assert_eq!(size.metrics.max_advance, 0x5555);

        unsafe { METRICS_SCALABLE_FINALIZE = saved };
    }

    #[test]
    fn ppem_rounding_uses_wrapping_retail_shift_pair() {
        let _guard = TEST_LOCK.lock();
        FINALIZE_CALLS.store(0, Ordering::SeqCst);

        // (x + 0x20) << 10 >> 16 truncated to u16: rounds at half-integers
        // for small ppem, wraps for huge ones, and yields 0 for the
        // negative-but-above--0x20 range.
        let cases: [(i32, u16); 6] = [
            (0, 0),
            (0x20, 1),      // exactly half: rounds up
            (0x1f, 0),
            ((64 << 6) - 0x21, 63),
            (0x003f_ffe0, 0),     // (x+0x20)<<10 overflows to 0
            (0x001f_ffff, 0x8000), // overflow preserves this high halfword
        ];
        for (raw, want) in cases {
            let mut strikes = [bitmap_size(0, raw, raw)];
            let mut size = FtSizeRec {
                face: ptr::null_mut(),
                driver: ptr::null_mut(),
                memory: ptr::null_mut(),
                metrics: zero_metrics(),
            };
            let mut face = face_with(0, strikes.as_mut_ptr().cast(), &mut size);
            unsafe { ft_select_metrics(&mut face, 0) };
            assert_eq!(size.metrics.x_ppem, want, "raw {raw:#x}");
            assert_eq!(size.metrics.y_ppem, want, "raw {raw:#x}");
        }
    }
}
