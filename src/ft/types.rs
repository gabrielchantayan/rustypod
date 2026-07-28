//! FreeType public geometry types as laid out in the retailOS binary
//! (verified against the ported functions' member offsets). `FT_Fixed`/
//! `FT_Pos` are 32-bit here; pointer fields widen naturally on 64-bit
//! hosts, which is fine — ported code accesses members by name, never by
//! raw offset.

/// `FT_Vector` — one 16.16 (or 26.6) fixed-point point. 8 bytes on ARM
/// (x @ +0, y @ +4).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FtVector {
    pub x: i32,
    pub y: i32,
}

/// `FT_Matrix` — 2x2 16.16 transform. 16 bytes on ARM
/// (xx @ +0, xy @ +4, yx @ +8, yy @ +12).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FtMatrix {
    pub xx: i32,
    pub xy: i32,
    pub yx: i32,
    pub yy: i32,
}

/// `FT_BBox` — control box. 16 bytes on ARM
/// (x_min @ +0, y_min @ +4, x_max @ +8, y_max @ +12).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FtBBox {
    pub x_min: i32,
    pub y_min: i32,
    pub x_max: i32,
    pub y_max: i32,
}

/// `FT_Outline` — glyph outline. 20 bytes on ARM: n_contours @ +0 (i16),
/// n_points @ +2 (i16), points @ +4, tags @ +8, contours @ +12,
/// flags @ +16.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FtOutline {
    pub n_contours: i16,
    pub n_points: i16,
    pub points: *mut FtVector,
    pub tags: *mut u8,
    pub contours: *mut i16,
    pub flags: i32,
}
