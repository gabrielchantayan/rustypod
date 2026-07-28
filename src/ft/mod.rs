//! FreeType 2 — the font engine statically linked into retailOS (the
//! `FT_Stream_Seek: invalid i/o` error strings and `ftcalc` fixed-point
//! kernels sit in the 0x0804c000..0x08051000 neighborhood). Ported
//! functions keep FreeType's public names in the crate's snake_case.
pub mod calc;
pub mod outline;
pub mod stream;
pub mod trace;
pub mod trig;
pub mod types;
