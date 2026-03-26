//! Memory management with privacy isolation.

use serde::{Deserialize, Serialize};
use aevor_core::tee::MemoryRange;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub range: MemoryRange,
    pub is_encrypted: bool,
    pub is_tee_protected: bool,
}

pub struct PrivateHeap { size_bytes: usize }
impl PrivateHeap {
    pub fn new(size_bytes: usize) -> Self { Self { size_bytes } }
    pub fn capacity(&self) -> usize { self.size_bytes }
}

pub struct PublicHeap { size_bytes: usize }
impl PublicHeap {
    pub fn new(size_bytes: usize) -> Self { Self { size_bytes } }
    pub fn capacity(&self) -> usize { self.size_bytes }
}

pub struct TeeProtectedMemory { region: MemoryRegion }
impl TeeProtectedMemory {
    /// Create a new TEE-protected memory region.
    pub fn new(range: MemoryRange) -> Self {
        Self { region: MemoryRegion { range, is_encrypted: true, is_tee_protected: true } }
    }
    /// The underlying memory region descriptor.
    pub fn region(&self) -> &MemoryRegion { &self.region }
    /// The raw memory range.
    pub fn range(&self) -> &MemoryRange { &self.region.range }
    /// Memory size in bytes.
    pub fn size_bytes(&self) -> u64 { self.region.range.length }
}

pub struct MemoryIsolation { regions: Vec<MemoryRegion> }
impl MemoryIsolation {
    pub fn new() -> Self { Self { regions: Vec::new() } }
    pub fn add_region(&mut self, r: MemoryRegion) { self.regions.push(r); }
}
impl Default for MemoryIsolation { fn default() -> Self { Self::new() } }

pub struct MemoryManager {
    pub private_heap: PrivateHeap,
    pub public_heap: PublicHeap,
    pub isolation: MemoryIsolation,
}

impl MemoryManager {
    pub fn new(private_bytes: usize, public_bytes: usize) -> Self {
        Self {
            private_heap: PrivateHeap::new(private_bytes),
            public_heap: PublicHeap::new(public_bytes),
            isolation: MemoryIsolation::new(),
        }
    }
}
