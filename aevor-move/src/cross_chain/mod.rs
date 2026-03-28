//! Move cross-chain interoperability extensions.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrossChainModule { pub name: String, pub target_chain: String }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cross_chain_module_stores_name_and_target() {
        let m = CrossChainModule { name: "bridge".into(), target_chain: "ethereum".into() };
        assert_eq!(m.name, "bridge");
        assert_eq!(m.target_chain, "ethereum");
    }

    #[test]
    fn cross_chain_module_different_chains() {
        let evm = CrossChainModule { name: "evm_bridge".into(), target_chain: "ethereum".into() };
        let btc = CrossChainModule { name: "utxo_bridge".into(), target_chain: "bitcoin".into() };
        assert_ne!(evm.target_chain, btc.target_chain);
    }
}
