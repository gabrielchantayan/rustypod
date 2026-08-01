//! C++ standard-library runtime: the container and string implementations
//! retailOS's application layer is built on. They live in the
//! 0x083c0000-0x083dffff block of osos (~1000 functions), separate from
//! the ARM ADS C runtime.
pub mod byte_key_map;
pub mod decoder_end_batch;
pub mod handle;
pub mod list_splice;
pub mod pair_header;
pub mod release;
pub mod string;
pub mod string_map;
pub mod string_object;
pub mod templates;
