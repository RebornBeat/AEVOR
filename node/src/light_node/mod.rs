//! Light node (header-only verification).

/// A light node that verifies block headers without downloading full blocks.
///
/// The `checkpoint` is a trusted block hash or height string from which the
/// light node begins header verification, avoiding the need to sync from genesis.
pub struct LightNode { checkpoint: Option<String> }
impl LightNode {
    /// Create a light node, optionally starting from a trusted `checkpoint`.
    pub fn new(checkpoint: Option<String>) -> Self { Self { checkpoint } }

    /// The trusted checkpoint this light node syncs from, if set.
    ///
    /// Returns `None` if the node syncs from genesis (no trusted anchor).
    pub fn checkpoint(&self) -> Option<&str> { self.checkpoint.as_deref() }

    /// Whether this light node has a trusted checkpoint anchor.
    pub fn has_checkpoint(&self) -> bool { self.checkpoint.is_some() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn light_node_with_checkpoint() {
        let n = LightNode::new(Some("0xABC".into()));
        assert!(n.has_checkpoint());
        assert_eq!(n.checkpoint(), Some("0xABC"));
    }

    #[test]
    fn light_node_without_checkpoint_syncs_from_genesis() {
        let n = LightNode::new(None);
        assert!(!n.has_checkpoint());
        assert!(n.checkpoint().is_none());
    }
}
