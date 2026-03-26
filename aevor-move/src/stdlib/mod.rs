//! AEVOR Move standard library modules.

pub struct AevorStdlib;
pub struct PrivacyModule;
pub struct TeeModule;
pub struct CryptoModule;
pub struct ObjectModule;
pub struct ConsensusModule;

impl AevorStdlib {
    pub fn module_names() -> &'static [&'static str] {
        &["aevor::privacy", "aevor::tee", "aevor::crypto", "aevor::object", "aevor::consensus"]
    }
}
