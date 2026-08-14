//! The retailOS JPEG decoder.
//!
//! Its state is a single global @ 0x08a0a79c: one decoder, no instance
//! handle, every entry point reaching it through a literal-pool word.
//! The parsers are spread across 0x0807xxxx (`FUN_0807a7b0` marker scan,
//! `FUN_0807ec24` entropy bit reader) and 0x080e9xxx..0x080edxxx
//! (`FUN_080e9eb4` `DHT`, plus the unnamed `SOF`/`SOS`/`DQT` blocks in
//! 0x080ea000..0x080ea400 and 0x080ed100..0x080ed320), while the source
//! bytes are produced by `FUN_08086ed0` @ 0x08086ed0 into a 2 KiB
//! double buffer.
//!
//! What pins the codec down as JPEG: `FUN_0807ec24`'s `0xff 0x00`
//! unstuffing, `FUN_080e9eb4`'s `Tc`/`Th` nibble split into separate DC
//! and AC table arrays, and the `"jpeg"`/`"tiff"`/`"pict"` format-name
//! table @ 0x08117cec.
//!
//! [`source`] ports the consumer end of the double buffer.
pub mod source;
