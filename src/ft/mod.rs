//! FreeType 2 — the font engine statically linked into retailOS (the
//! `FT_Stream_Seek: invalid i/o` error strings and `ftcalc` fixed-point
//! kernels sit in the 0x0804c000..0x08051000 neighborhood). Ported
//! functions keep FreeType's public names in the crate's snake_case.
pub mod arith;
pub mod buffer;
pub mod buffer_skip;
pub mod calc;
pub mod charmap;
pub mod cff_builder;
pub mod cff_pshinter_callback;
pub mod cff_index;
pub mod cff_parse_fixed;
pub mod cff_sid;
pub mod t1_builder;
pub mod t1_pfb_header;
pub mod conditional_offset;
pub mod interpolate_delta;
pub mod error;
pub mod face;
pub mod glyph_slot;
pub mod glyph_loader;
pub mod list;
pub mod memory;
pub mod module;
pub mod linked_module_find_by_class;
pub mod metrics;
pub mod outline;
pub mod offset_buffer;
pub mod service;
pub mod select_metrics;
pub mod size;
pub mod service_metadata;
pub mod stream;
pub mod resource_fork;
pub mod stream_read_bounded;
pub mod stream_read_capped;
pub mod stream_skip;
pub mod system;
pub mod selection;
pub mod sfnt;
pub mod trace;
pub mod trig;
pub mod word_cursor;
pub mod too_many_hints;
pub mod types;
