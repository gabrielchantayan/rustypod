//! ADS stdio stream layer (fread et al., semihost-backed).
pub mod cg_stack_slot;
pub mod decoder_initialize;
pub mod fread;
pub mod ftell;
pub mod fwrite;
pub mod getc_core;
pub mod linebuf_putc;
pub mod seek_core;
pub mod scan_stream_setup;
pub mod semihost;
pub mod stdio_init;
pub mod stream_file;
pub mod stream_flags;
