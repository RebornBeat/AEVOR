use std::fmt;
use std::sync::Arc;
use std::collections::HashMap;

use tokio::sync::{RwLock, Mutex};
use reed_solomon_erasure::{ReedSolomon, galois_8, Error as ReedSolomonError};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

use crate::error::{AevorError, Result};

/// Represents a data fragment in the erasure coding scheme
#[derive(Clone, Serialize, Deserialize)]
pub struct DataFragment {
    /// Fragment index
    pub index: usize,
    
    /// Original data shard index
    pub shard_index: usize,
    
    /// The actual fragment data
    pub data: Vec<u8>,
    
    /// The hash of the original data
    pub original_hash: Vec<u8>,
    
    /// Total number of data shards
    pub total_data_shards: usize,
    
    /// Total number of parity shards
    pub total_parity_shards: usize,
    
    /// The combined data and parity shard length in bytes
    pub shard_len: usize,
}

/// Represents a parity fragment in the erasure coding scheme
#[derive(Clone, Serialize, Deserialize)]
pub struct ParityFragment {
    /// Fragment index
    pub index: usize,
    
    /// Original parity shard index
    pub shard_index: usize,
    
    /// The actual fragment data
    pub data: Vec<u8>,
    
    /// The hash of the original data
    pub original_hash: Vec<u8>,
    
    /// Total number of data shards
    pub total_data_shards: usize,
    
    /// Total number of parity shards
    pub total_parity_shards: usize,
    
    /// The combined data and parity shard length in bytes
    pub shard_len: usize,
}

impl fmt::Debug for DataFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataFragment")
            .field("index", &self.index)
            .field("shard_index", &self.shard_index)
            .field("data_len", &self.data.len())
            .field("original_hash", &hex::encode(&self.original_hash))
            .field("total_data_shards", &self.total_data_shards)
            .field("total_parity_shards", &self.total_parity_shards)
            .field("shard_len", &self.shard_len)
            .finish()
    }
}

impl fmt::Debug for ParityFragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParityFragment")
            .field("index", &self.index)
            .field("shard_index", &self.shard_index)
            .field("data_len", &self.data.len())
            .field("original_hash", &hex::encode(&self.original_hash))
            .field("total_data_shards", &self.total_data_shards)
            .field("total_parity_shards", &self.total_parity_shards)
            .field("shard_len", &self.shard_len)
            .finish()
    }
}

/// Fragment type (data or parity)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FragmentType {
    /// Data fragment
    Data,
    
    /// Parity fragment
    Parity,
}

/// Cache entry for storing fragments
#[derive(Debug, Clone)]
struct FragmentCacheEntry {
    /// The original data
    original_data: Option<Vec<u8>>,
    
    /// Data fragments
    data_fragments: Vec<Option<DataFragment>>,
    
    /// Parity fragments
    parity_fragments: Vec<Option<ParityFragment>>,
    
    /// Whether the data has been reconstructed
    reconstructed: bool,
    
    /// Timestamp of the last access
    last_access: u64,
}

/// Erasure coding implementation for data availability
pub struct ErasureCoding {
    /// Number of data shards (K in K-of-N)
    data_shards: usize,
    
    /// Total number of shards (N in K-of-N)
    total_shards: usize,
    
    /// Reed-Solomon encoder/decoder
    rs_codec: Arc<Mutex<ReedSolomon<galois_8::Field>>>,
    
    /// Cache of fragments being reconstructed
    fragment_cache: Arc<RwLock<HashMap<Vec<u8>, FragmentCacheEntry>>>,
    
    /// Maximum cache size in number of entries
    max_cache_size: usize,
    
    /// Maximum age of cache entries in seconds
    max_cache_age: u64,
}

impl ErasureCoding {
    /// Creates a new ErasureCoding instance
    pub fn new(data_shards: usize, total_shards: usize) -> Result<Self> {
        // Validate parameters
        if data_shards == 0 {
            return Err(AevorError::validation("Data shards must be greater than 0"));
        }
        
        if total_shards <= data_shards {
            return Err(AevorError::validation("Total shards must be greater than data shards"));
        }
        
        // Create Reed-Solomon codec
        let parity_shards = total_shards - data_shards;
        let rs_codec = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| AevorError::network(format!("Failed to create Reed-Solomon codec: {}", e)))?;
        
        Ok(Self {
            data_shards,
            total_shards,
            rs_codec: Arc::new(Mutex::new(rs_codec)),
            fragment_cache: Arc::new(RwLock::new(HashMap::new())),
            max_cache_size: 1000, // Default value
            max_cache_age: 3600,  // Default 1 hour
        })
    }
    
    /// Gets the number of data shards
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }
    
    /// Gets the total number of shards
    pub fn total_shards(&self) -> usize {
        self.total_shards
    }
    
    /// Gets the number of parity shards
    pub fn parity_shards(&self) -> usize {
        self.total_shards - self.data_shards
    }
    
    /// Sets the maximum cache size
    pub fn set_max_cache_size(&mut self, size: usize) {
        self.max_cache_size = size;
    }
    
    /// Sets the maximum cache age in seconds
    pub fn set_max_cache_age(&mut self, age: u64) {
        self.max_cache_age = age;
    }
    
    /// Encodes data into fragments
    pub async fn encode(&self, data: &[u8], original_hash: Vec<u8>) -> Result<(Vec<DataFragment>, Vec<ParityFragment>)> {
        // Determine the shard size
        // Each shard must be the same size, so we may need to pad the last shard
        let shard_size = if data.len() % self.data_shards == 0 {
            data.len() / self.data_shards
        } else {
            (data.len() / self.data_shards) + 1
        };
        
        // Create shards
        let mut shards = Vec::with_capacity(self.total_shards);
        
        // Prepare data shards
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min((i + 1) * shard_size, data.len());
            
            let mut shard = Vec::with_capacity(shard_size);
            
            if start < data.len() {
                shard.extend_from_slice(&data[start..end]);
            }
            
            // Pad the shard if necessary
            while shard.len() < shard_size {
                shard.push(0);
            }
            
            shards.push(shard);
        }
        
        // Add empty parity shards
        for _ in 0..self.parity_shards() {
            shards.push(vec![0; shard_size]);
        }
        
        // Create and lock mutable references to shards for the encoding process
        let mut shard_ptrs: Vec<_> = shards.iter_mut().map(|shard| shard.as_mut_slice()).collect();
        
        // Encode the data (compute parity shards)
        let rs_codec = self.rs_codec.lock().await;
        rs_codec.encode(&mut shard_ptrs)
            .map_err(|e| AevorError::network(format!("Reed-Solomon encoding failed: {}", e)))?;
        
        // Create data fragments
        let mut data_fragments = Vec::with_capacity(self.data_shards);
        for (i, shard) in shards.iter().take(self.data_shards).enumerate() {
            data_fragments.push(DataFragment {
                index: i,
                shard_index: i,
                data: shard.clone(),
                original_hash: original_hash.clone(),
                total_data_shards: self.data_shards,
                total_parity_shards: self.parity_shards(),
                shard_len: shard_size,
            });
        }
        
        // Create parity fragments
        let mut parity_fragments = Vec::with_capacity(self.parity_shards());
        for (i, shard) in shards.iter().skip(self.data_shards).enumerate() {
            parity_fragments.push(ParityFragment {
                index: self.data_shards + i,
                shard_index: i,
                data: shard.clone(),
                original_hash: original_hash.clone(),
                total_data_shards: self.data_shards,
                total_parity_shards: self.parity_shards(),
                shard_len: shard_size,
            });
        }
        
        // Add to cache
        self.add_to_cache(original_hash.clone(), data.to_vec(), data_fragments.clone(), parity_fragments.clone()).await;
        
        Ok((data_fragments, parity_fragments))
    }
    
    /// Decodes fragments back into the original data
    pub async fn decode(&self, 
                        fragments: &[impl Fragment], 
                        original_hash: &[u8]) -> Result<Vec<u8>> {
        // Check if we have the data in cache
        if let Some(data) = self.get_from_cache(original_hash).await {
            return Ok(data);
        }
        
        // Check if we have enough fragments
        if fragments.len() < self.data_shards {
            return Err(AevorError::network(format!(
                "Not enough fragments to reconstruct data: {} < {}",
                fragments.len(),
                self.data_shards
            )));
        }
        
        // Get the metadata from the first fragment
        let shard_len = fragments[0].get_shard_len();
        let total_data_shards = fragments[0].get_total_data_shards();
        let total_parity_shards = fragments[0].get_total_parity_shards();
        
        // Validate the fragment metadata
        if total_data_shards != self.data_shards || 
           (total_data_shards + total_parity_shards) != self.total_shards {
            return Err(AevorError::validation(
                "Fragment metadata doesn't match the codec parameters"
            ));
        }
        
        // Create shards
        let mut shards = vec![None; self.total_shards];
        
        // Fill in the shards from the fragments
        for fragment in fragments {
            let index = fragment.get_index();
            if index < self.total_shards {
                shards[index] = Some(fragment.get_data().clone());
            }
        }
        
        // Check if we need to reconstruct
        let missing_shards = shards.iter().filter(|s| s.is_none()).count();
        
        if missing_shards > 0 {
            // Collect present shards
            let present_indices: Vec<_> = shards.iter().enumerate()
                .filter_map(|(i, shard)| if shard.is_some() { Some(i) } else { None })
                .collect();
            
            // Prepare shards for reconstruction
            let mut shard_data: Vec<Vec<u8>> = shards.into_iter()
                .map(|shard| shard.unwrap_or_else(|| vec![0; shard_len]))
                .collect();
            
            // Create mutable references to shards
            let mut shard_ptrs: Vec<_> = shard_data.iter_mut().map(|shard| shard.as_mut_slice()).collect();
            
            // Reconstruct the data
            let rs_codec = self.rs_codec.lock().await;
            rs_codec.reconstruct_data(&mut shard_ptrs, &present_indices)
                .map_err(|e| AevorError::network(format!("Reed-Solomon reconstruction failed: {}", e)))?;
            
            // Extract the data from the reconstructed shards
            let mut result = Vec::new();
            for i in 0..self.data_shards {
                result.extend_from_slice(&shard_data[i]);
            }
            
            // Truncate any padding
            let original_length = result.len();
            
            // We don't know the exact original length, so we'll return the reconstructed data as is
            
            // Add to cache
            let mut data_fragments = Vec::with_capacity(self.data_shards);
            let mut parity_fragments = Vec::with_capacity(self.parity_shards());
            
            for (i, shard) in shard_data.iter().take(self.data_shards).enumerate() {
                data_fragments.push(Some(DataFragment {
                    index: i,
                    shard_index: i,
                    data: shard.clone(),
                    original_hash: original_hash.to_vec(),
                    total_data_shards: self.data_shards,
                    total_parity_shards: self.parity_shards(),
                    shard_len,
                }));
            }
            
            for (i, shard) in shard_data.iter().skip(self.data_shards).enumerate() {
                parity_fragments.push(Some(ParityFragment {
                    index: self.data_shards + i,
                    shard_index: i,
                    data: shard.clone(),
                    original_hash: original_hash.to_vec(),
                    total_data_shards: self.data_shards,
                    total_parity_shards: self.parity_shards(),
                    shard_len,
                }));
            }
            
            self.add_reconstructed_to_cache(
                original_hash.to_vec(), 
                result.clone(), 
                data_fragments, 
                parity_fragments
            ).await;
            
            Ok(result)
        } else {
            // All shards are present, just combine the data shards
            let mut result = Vec::new();
            for i in 0..self.data_shards {
                if let Some(shard) = &shards[i] {
                    result.extend_from_slice(shard);
                }
            }
            
            // We don't know the exact original length, so we'll return all the data
            
            // Add to cache
            let mut data_fragments = Vec::with_capacity(self.data_shards);
            let mut parity_fragments = Vec::with_capacity(self.parity_shards());
            
            for i in 0..self.data_shards {
                if let Some(shard) = &shards[i] {
                    data_fragments.push(Some(DataFragment {
                        index: i,
                        shard_index: i,
                        data: shard.clone(),
                        original_hash: original_hash.to_vec(),
                        total_data_shards: self.data_shards,
                        total_parity_shards: self.parity_shards(),
                        shard_len,
                    }));
                } else {
                    data_fragments.push(None);
                }
            }
            
            for i in 0..self.parity_shards() {
                let shard_index = self.data_shards + i;
                if let Some(shard) = &shards[shard_index] {
                    parity_fragments.push(Some(ParityFragment {
                        index: shard_index,
                        shard_index: i,
                        data: shard.clone(),
                        original_hash: original_hash.to_vec(),
                        total_data_shards: self.data_shards,
                        total_parity_shards: self.parity_shards(),
                        shard_len,
                    }));
                } else {
                    parity_fragments.push(None);
                }
            }
            
            self.add_reconstructed_to_cache(
                original_hash.to_vec(), 
                result.clone(), 
                data_fragments, 
                parity_fragments
            ).await;
            
            Ok(result)
        }
    }
    
    /// Verifies if the given fragments can reconstruct the original data
    pub async fn can_reconstruct(&self, fragments: &[impl Fragment]) -> bool {
        if fragments.len() < self.data_shards {
            return false;
        }
        
        // Check if the fragments are from the same set
        if fragments.len() > 1 {
            let original_hash = fragments[0].get_original_hash();
            for fragment in fragments.iter().skip(1) {
                if fragment.get_original_hash() != original_hash {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// Samples from the fragments to verify data availability
    pub async fn sample_availability<T: Fragment + Clone>(&self, 
                                   fragments: &[T], 
                                   sample_count: usize) -> Result<bool> {
        if fragments.is_empty() {
            return Ok(false);
        }
        
        // Get unique indices
        let mut indices: Vec<usize> = fragments.iter().map(|f| f.get_index()).collect();
        indices.sort();
        indices.dedup();
        
        // We need at least data_shards unique indices to reconstruct
        if indices.len() < self.data_shards {
            return Ok(false);
        }
        
        // If we have all shards, no need to sample
        if indices.len() == self.total_shards {
            return Ok(true);
        }
        
        // Sample random subsets and try to decode
        let mut rng = thread_rng();
        
        for _ in 0..sample_count {
            // Randomly select data_shards indices
            let sample_indices = if indices.len() <= self.data_shards {
                indices.clone()
            } else {
                // Shuffle and take the first data_shards
                let mut indices_copy = indices.clone();
                for i in 0..indices_copy.len() {
                    let j = rng.gen_range(0..indices_copy.len());
                    indices_copy.swap(i, j);
                }
                indices_copy.truncate(self.data_shards);
                indices_copy
            };
            
            // Get the fragments for these indices
            let sample_fragments: Vec<_> = fragments.iter()
                .filter(|f| sample_indices.contains(&f.get_index()))
                .cloned()
                .collect();
            
            // If we don't have enough fragments, this sample fails
            if sample_fragments.len() < self.data_shards {
                continue;
            }
            
            // Try to reconstruct using just these fragments
            let original_hash = sample_fragments[0].get_original_hash();
            
            // Prepare shards for reconstruction
            let mut shards = vec![None; self.total_shards];
            
            // Fill in the shards from the fragments
            for fragment in &sample_fragments {
                let index = fragment.get_index();
                shards[index] = Some(fragment.get_data().clone());
            }
            
            // Prepare shards for reconstruction
            let shard_len = sample_fragments[0].get_shard_len();
            let mut shard_data: Vec<Vec<u8>> = shards.into_iter()
                .map(|shard| shard.unwrap_or_else(|| vec![0; shard_len]))
                .collect();
            
            // Create mutable references to shards
            let mut shard_ptrs: Vec<_> = shard_data.iter_mut().map(|shard| shard.as_mut_slice()).collect();
            
            // Try to reconstruct the data
            let present_indices: Vec<_> = sample_fragments.iter().map(|f| f.get_index()).collect();
            
            let rs_codec = self.rs_codec.lock().await;
            match rs_codec.reconstruct_data(&mut shard_ptrs, &present_indices) {
                Ok(_) => return Ok(true),
                Err(_) => continue,
            }
        }
        
        // If all samples failed, data is likely not available
        Ok(false)
    }
    
    /// Checks if a fragment is valid
    pub fn is_valid_fragment<T: Fragment>(&self, fragment: &T) -> bool {
        // Check if the fragment matches our codec parameters
        if fragment.get_total_data_shards() != self.data_shards {
            return false;
        }
        
        if fragment.get_total_parity_shards() != self.parity_shards() {
            return false;
        }
        
        // Check if the index is valid
        let index = fragment.get_index();
        if index >= self.total_shards {
            return false;
        }
        
        // Additional validation could be performed here
        // For example, checking the fragment size
        
        true
    }
    
    /// Cleans up old cache entries
    pub async fn cleanup_cache(&self) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut cache = self.fragment_cache.write().await;
        
        // Remove entries that are too old
        cache.retain(|_, entry| {
            now - entry.last_access < self.max_cache_age
        });
        
        // If the cache is still too large, remove the oldest entries
        if cache.len() > self.max_cache_size {
            // Convert to a vec to sort by timestamp
            let mut entries: Vec<_> = cache.iter().collect();
            entries.sort_by_key(|(_, entry)| entry.last_access);
            
            // Keep only the newest max_cache_size entries
            let to_remove: Vec<_> = entries
                .iter()
                .take(entries.len() - self.max_cache_size)
                .map(|(key, _)| (*key).clone())
                .collect();
            
            for key in to_remove {
                cache.remove(&key);
            }
        }
    }
    
    /// Adds fragments to the cache
    async fn add_to_cache(&self, 
                         original_hash: Vec<u8>, 
                         original_data: Vec<u8>,
                         data_fragments: Vec<DataFragment>,
                         parity_fragments: Vec<ParityFragment>) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut cache = self.fragment_cache.write().await;
        
        // Create a new cache entry
        let mut entry = FragmentCacheEntry {
            original_data: Some(original_data),
            data_fragments: vec![None; self.data_shards],
            parity_fragments: vec![None; self.parity_shards()],
            reconstructed: true, // We have the original data
            last_access: now,
        };
        
        // Add data fragments
        for fragment in data_fragments {
            let index = fragment.shard_index;
            if index < entry.data_fragments.len() {
                entry.data_fragments[index] = Some(fragment);
            }
        }
        
        // Add parity fragments
        for fragment in parity_fragments {
            let index = fragment.shard_index;
            if index < entry.parity_fragments.len() {
                entry.parity_fragments[index] = Some(fragment);
            }
        }
        
        // Add to cache
        cache.insert(original_hash, entry);
        
        // Clean up cache if it's getting too large
        if cache.len() > self.max_cache_size {
            drop(cache); // Release the write lock
            self.cleanup_cache().await;
        }
    }
    
    /// Adds reconstructed fragments to the cache
    async fn add_reconstructed_to_cache(&self,
                                       original_hash: Vec<u8>,
                                       original_data: Vec<u8>,
                                       data_fragments: Vec<Option<DataFragment>>,
                                       parity_fragments: Vec<Option<ParityFragment>>) {
        let now = chrono::Utc::now().timestamp() as u64;
        let mut cache = self.fragment_cache.write().await;
        
        // Create a new cache entry
        let entry = FragmentCacheEntry {
            original_data: Some(original_data),
            data_fragments,
            parity_fragments,
            reconstructed: true,
            last_access: now,
        };
        
        // Add to cache
        cache.insert(original_hash, entry);
        
        // Clean up cache if it's getting too large
        if cache.len() > self.max_cache_size {
            drop(cache); // Release the write lock
            self.cleanup_cache().await;
        }
    }
    
    /// Gets data from the cache
    async fn get_from_cache(&self, original_hash: &[u8]) -> Option<Vec<u8>> {
        let mut cache = self.fragment_cache.write().await;
        
        if let Some(entry) = cache.get_mut(original_hash) {
            // Update last access time
            entry.last_access = chrono::Utc::now().timestamp() as u64;
            
            // Return the original data if available
            entry.original_data.clone()
        } else {
            None
        }
    }
    
    /// Gets fragments from the cache
    pub async fn get_fragments_from_cache(&self, 
                                         original_hash: &[u8],
                                         fragment_type: FragmentType) -> Option<Vec<Box<dyn Fragment>>> {
        let mut cache = self.fragment_cache.write().await;
        
        if let Some(entry) = cache.get_mut(original_hash) {
            // Update last access time
            entry.last_access = chrono::Utc::now().timestamp() as u64;
            
            match fragment_type {
                FragmentType::Data => {
                    let fragments: Vec<Box<dyn Fragment>> = entry.data_fragments.iter()
                        .filter_map(|f| {
                            f.as_ref().map(|fragment| Box::new(fragment.clone()) as Box<dyn Fragment>)
                        })
                        .collect();
                    
                    if fragments.is_empty() {
                        None
                    } else {
                        Some(fragments)
                    }
                },
                FragmentType::Parity => {
                    let fragments: Vec<Box<dyn Fragment>> = entry.parity_fragments.iter()
                        .filter_map(|f| {
                            f.as_ref().map(|fragment| Box::new(fragment.clone()) as Box<dyn Fragment>)
                        })
                        .collect();
                    
                    if fragments.is_empty() {
                        None
                    } else {
                        Some(fragments)
                    }
                },
            }
        } else {
            None
        }
    }
    
    /// Compute the total size of all fragments for a given data
    pub fn compute_total_fragments_size(&self, data_size: usize) -> usize {
        // Determine the shard size
        let shard_size = if data_size % self.data_shards == 0 {
            data_size / self.data_shards
        } else {
            (data_size / self.data_shards) + 1
        };
        
        // Total size is shard_size * total_shards
        shard_size * self.total_shards
    }
    
    /// Computes the expansion factor (total fragments size / original data size)
    pub fn compute_expansion_factor(&self, data_size: usize) -> f64 {
        let total_fragments_size = self.compute_total_fragments_size(data_size);
        total_fragments_size as f64 / data_size as f64
    }
}

/// Trait for fragments (data or parity)
pub trait Fragment: Send + Sync {
    /// Gets the fragment index
    fn get_index(&self) -> usize;
    
    /// Gets the fragment data
    fn get_data(&self) -> &Vec<u8>;
    
    /// Gets the original data hash
    fn get_original_hash(&self) -> &[u8];
    
    /// Gets the total number of data shards
    fn get_total_data_shards(&self) -> usize;
    
    /// Gets the total number of parity shards
    fn get_total_parity_shards(&self) -> usize;
    
    /// Gets the shard length
    fn get_shard_len(&self) -> usize;
    
    /// Gets the fragment type
    fn get_fragment_type(&self) -> FragmentType;
    
    /// Clones the fragment as a Box<dyn Fragment>
    fn clone_boxed(&self) -> Box<dyn Fragment>;
}

impl Fragment for DataFragment {
    fn get_index(&self) -> usize {
        self.index
    }
    
    fn get_data(&self) -> &Vec<u8> {
        &self.data
    }
    
    fn get_original_hash(&self) -> &[u8] {
        &self.original_hash
    }
    
    fn get_total_data_shards(&self) -> usize {
        self.total_data_shards
    }
    
    fn get_total_parity_shards(&self) -> usize {
        self.total_parity_shards
    }
    
    fn get_shard_len(&self) -> usize {
        self.shard_len
    }
    
    fn get_fragment_type(&self) -> FragmentType {
        FragmentType::Data
    }
    
    fn clone_boxed(&self) -> Box<dyn Fragment> {
        Box::new(self.clone())
    }
}

impl Fragment for ParityFragment {
    fn get_index(&self) -> usize {
        self.index
    }
    
    fn get_data(&self) -> &Vec<u8> {
        &self.data
    }
    
    fn get_original_hash(&self) -> &[u8] {
        &self.original_hash
    }
    
    fn get_total_data_shards(&self) -> usize {
        self.total_data_shards
    }
    
    fn get_total_parity_shards(&self) -> usize {
        self.total_parity_shards
    }
    
    fn get_shard_len(&self) -> usize {
        self.shard_len
    }
    
    fn get_fragment_type(&self) -> FragmentType {
        FragmentType::Parity
    }
    
    fn clone_boxed(&self) -> Box<dyn Fragment> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_erasure_coding_encode_decode() {
        // Create a test erasure coding instance
        let data_shards = 4;
        let total_shards = 6;
        let erasure_coding = ErasureCoding::new(data_shards, total_shards).unwrap();
        
        // Test data
        let data = b"This is a test of the erasure coding system. It should be able to reconstruct the data from a subset of fragments.".to_vec();
        let original_hash = blake3::hash(&data).as_bytes().to_vec();
        
        // Encode the data
        let (data_fragments, parity_fragments) = erasure_coding.encode(&data, original_hash.clone()).await.unwrap();
        
        // Check that we have the right number of fragments
        assert_eq!(data_fragments.len(), data_shards);
        assert_eq!(parity_fragments.len(), total_shards - data_shards);
        
        // Check that the fragments have the right metadata
        for fragment in &data_fragments {
            assert_eq!(fragment.total_data_shards, data_shards);
            assert_eq!(fragment.total_parity_shards, total_shards - data_shards);
            assert_eq!(fragment.original_hash, original_hash);
        }
        
        for fragment in &parity_fragments {
            assert_eq!(fragment.total_data_shards, data_shards);
            assert_eq!(fragment.total_parity_shards, total_shards - data_shards);
            assert_eq!(fragment.original_hash, original_hash);
        }
        
        // Test decoding with all fragments
        let all_fragments: Vec<Box<dyn Fragment>> = data_fragments.iter()
            .map(|f| Box::new(f.clone()) as Box<dyn Fragment>)
            .chain(parity_fragments.iter().map(|f| Box::new(f.clone()) as Box<dyn Fragment>))
            .collect();
        
        let decoded_data = erasure_coding.decode(&all_fragments, &original_hash).await.unwrap();
        
        // Check that the decoded data matches the original
        assert_eq!(decoded_data[..data.len()], data[..]);
        
        // Test decoding with only data fragments
        let data_only_fragments: Vec<Box<dyn Fragment>> = data_fragments.iter()
            .map(|f| Box::new(f.clone()) as Box<dyn Fragment>)
            .collect();
        
        let decoded_data = erasure_coding.decode(&data_only_fragments, &original_hash).await.unwrap();
        
        // Check that the decoded data matches the original
        assert_eq!(decoded_data[..data.len()], data[..]);
        
        // Test decoding with some data and some parity fragments
        let mut mixed_fragments: Vec<Box<dyn Fragment>> = Vec::new();
        
        // Add 2 data fragments
        mixed_fragments.push(Box::new(data_fragments[0].clone()));
        mixed_fragments.push(Box::new(data_fragments[1].clone()));
        
        // Add 2 parity fragments
        mixed_fragments.push(Box::new(parity_fragments[0].clone()));
        mixed_fragments.push(Box::new(parity_fragments[1].clone()));
        
        let decoded_data = erasure_coding.decode(&mixed_fragments, &original_hash).await.unwrap();
        
        // Check that the decoded data matches the original
        assert_eq!(decoded_data[..data.len()], data[..]);
        
        // Test that decoding fails with too few fragments
        let too_few_fragments: Vec<Box<dyn Fragment>> = vec![
            Box::new(data_fragments[0].clone()),
            Box::new(data_fragments[1].clone()),
            Box::new(parity_fragments[0].clone()),
        ];
        
        let result = erasure_coding.decode(&too_few_fragments, &original_hash).await;
        assert!(result.is_err());
        
        // Test availability sampling
        let fragments_vec: Vec<DataFragment> = data_fragments.clone();
        let can_reconstruct = erasure_coding.sample_availability(&fragments_vec, 10).await.unwrap();
        assert!(can_reconstruct);
    }
    
    #[tokio::test]
    async fn test_erasure_coding_cache() {
        // Create a test erasure coding instance
        let data_shards = 4;
        let total_shards = 6;
        let mut erasure_coding = ErasureCoding::new(data_shards, total_shards).unwrap();
        
        // Set cache parameters
        erasure_coding.set_max_cache_size(10);
        erasure_coding.set_max_cache_age(60); // 1 minute
        
        // Test data
        let data = b"This is a test of the erasure coding cache.".to_vec();
        let original_hash = blake3::hash(&data).as_bytes().to_vec();
        
        // Encode the data
        let (data_fragments, parity_fragments) = erasure_coding.encode(&data, original_hash.clone()).await.unwrap();
        
        // Check that the data is in the cache
        let cached_data = erasure_coding.get_from_cache(&original_hash).await;
        assert!(cached_data.is_some());
        assert_eq!(cached_data.unwrap(), data);
        
        // Check that fragments are in the cache
        let cached_data_fragments = erasure_coding.get_fragments_from_cache(&original_hash, FragmentType::Data).await;
        assert!(cached_data_fragments.is_some());
        assert_eq!(cached_data_fragments.unwrap().len(), data_shards);
        
        let cached_parity_fragments = erasure_coding.get_fragments_from_cache(&original_hash, FragmentType::Parity).await;
        assert!(cached_parity_fragments.is_some());
        assert_eq!(cached_parity_fragments.unwrap().len(), total_shards - data_shards);
        
        // Test cache cleanup
        erasure_coding.cleanup_cache().await;
        
        // Data should still be in cache after cleanup
        let cached_data = erasure_coding.get_from_cache(&original_hash).await;
        assert!(cached_data.is_some());
    }
    
    #[test]
    fn test_compute_total_fragments_size() {
        // Create a test erasure coding instance
        let data_shards = 4;
        let total_shards = 6;
        let erasure_coding = ErasureCoding::new(data_shards, total_shards).unwrap();
        
        // Test with data size that divides evenly
        let data_size = 1000;
        let expected_shard_size = data_size / data_shards;
        let expected_total_size = expected_shard_size * total_shards;
        
        assert_eq!(erasure_coding.compute_total_fragments_size(data_size), expected_total_size);
        
        // Test with data size that doesn't divide evenly
        let data_size = 1001;
        let expected_shard_size = (data_size / data_shards) + 1;
        let expected_total_size = expected_shard_size * total_shards;
        
        assert_eq!(erasure_coding.compute_total_fragments_size(data_size), expected_total_size);
    }
    
    #[test]
    fn test_compute_expansion_factor() {
        // Create a test erasure coding instance
        let data_shards = 4;
        let total_shards = 6;
        let erasure_coding = ErasureCoding::new(data_shards, total_shards).unwrap();
        
        // Test with data size that divides evenly
        let data_size = 1000;
        let expected_factor = total_shards as f64 / data_shards as f64;
        
        assert!((erasure_coding.compute_expansion_factor(data_size) - expected_factor).abs() < 0.001);
        
        // Test with data size that doesn't divide evenly
        let data_size = 1001;
        let expected_shard_size = (data_size / data_shards) + 1;
        let expected_total_size = expected_shard_size * total_shards;
        let expected_factor = expected_total_size as f64 / data_size as f64;
        
        assert!((erasure_coding.compute_expansion_factor(data_size) - expected_factor).abs() < 0.001);
    }
}
