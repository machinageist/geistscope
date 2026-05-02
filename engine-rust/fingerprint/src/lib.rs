// Author: Jeff
// Date: 2026-05-01
// Description: Tech-stack fingerprinting — HTTP response → detected technologies + wordlist hints

pub mod detect;
pub mod wordlists;

pub use detect::{fingerprint_url, Fingerprint};
pub use wordlists::tech_wordlist;
