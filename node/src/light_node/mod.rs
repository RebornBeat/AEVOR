//! Light node (header-only verification).
pub struct LightNode { checkpoint: Option<String> }
impl LightNode {
    pub fn new(checkpoint: Option<String>) -> Self { Self { checkpoint } }
}
