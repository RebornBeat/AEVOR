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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdlib_has_five_core_modules() {
        assert_eq!(AevorStdlib::module_names().len(), 5);
    }

    #[test]
    fn stdlib_includes_privacy_module() {
        assert!(AevorStdlib::module_names().contains(&"aevor::privacy"));
    }

    #[test]
    fn stdlib_includes_tee_module() {
        assert!(AevorStdlib::module_names().contains(&"aevor::tee"));
    }

    #[test]
    fn stdlib_includes_consensus_module() {
        assert!(AevorStdlib::module_names().contains(&"aevor::consensus"));
    }
}
