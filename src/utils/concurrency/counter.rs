use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A thread-safe counter for concurrent operations
pub struct AtomicCounter {
    /// Inner counter value
    counter: Arc<AtomicUsize>,
}

impl AtomicCounter {
    /// Creates a new atomic counter starting at zero
    pub fn new() -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    /// Creates a new atomic counter with an initial value
    pub fn with_value(value: usize) -> Self {
        Self {
            counter: Arc::new(AtomicUsize::new(value)),
        }
    }
    
    /// Gets the current counter value
    pub fn value(&self) -> usize {
        self.counter.load(Ordering::SeqCst)
    }
    
    /// Increments the counter and returns the previous value
    pub fn increment(&self) -> usize {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }
    
    /// Increments the counter by a specified amount and returns the previous value
    pub fn add(&self, value: usize) -> usize {
        self.counter.fetch_add(value, Ordering::SeqCst)
    }
    
    /// Decrements the counter and returns the previous value
    pub fn decrement(&self) -> usize {
        self.counter.fetch_sub(1, Ordering::SeqCst)
    }
    
    /// Decrements the counter by a specified amount and returns the previous value
    pub fn subtract(&self, value: usize) -> usize {
        self.counter.fetch_sub(value, Ordering::SeqCst)
    }
    
    /// Sets the counter to a specific value and returns the previous value
    pub fn set(&self, value: usize) -> usize {
        self.counter.swap(value, Ordering::SeqCst)
    }
    
    /// Resets the counter to zero and returns the previous value
    pub fn reset(&self) -> usize {
        self.set(0)
    }
    
    /// Increments the counter only if the current value equals the expected value
    pub fn compare_and_increment(&self, expected: usize) -> bool {
        self.counter.compare_exchange(
            expected,
            expected + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ).is_ok()
    }
    
    /// Sets the counter to a new value only if the current value equals the expected value
    pub fn compare_and_set(&self, expected: usize, new: usize) -> bool {
        self.counter.compare_exchange(
            expected,
            new,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ).is_ok()
    }
    
    /// Creates a clone of this counter that refers to the same underlying value
    pub fn clone(&self) -> Self {
        Self {
            counter: Arc::clone(&self.counter),
        }
    }
    
    /// Creates a weak tracker that will increment on creation and decrement on drop
    pub fn tracker(&self) -> CounterTracker {
        self.increment();
        CounterTracker {
            counter: Arc::clone(&self.counter),
        }
    }
}

impl Default for AtomicCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for AtomicCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AtomicCounter")
            .field("value", &self.value())
            .finish()
    }
}

impl fmt::Display for AtomicCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value())
    }
}

/// A tracker that increments the counter on creation and decrements on drop
pub struct CounterTracker {
    /// Reference to the counter
    counter: Arc<AtomicUsize>,
}

impl Drop for CounterTracker {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl fmt::Debug for CounterTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CounterTracker")
            .field("counter_value", &self.counter.load(Ordering::SeqCst))
            .finish()
    }
}
