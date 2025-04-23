// Aevor Concurrency Module
//
// This module provides asynchronous concurrency primitives for the Aevor blockchain,
// including mutexes, semaphores, and counters optimized for high-throughput scenarios.

pub mod mutex;
pub mod semaphore;
pub mod counter;
pub mod limiter;
pub mod rwlock;

// Re-export commonly used types
pub use mutex::{AsyncMutex, AsyncMutexGuard};
pub use semaphore::{AsyncSemaphore, AsyncSemaphorePermit};
pub use counter::AtomicCounter;
pub use limiter::ConcurrencyLimiter;
pub use rwlock::{AsyncRwLock, AsyncRwLockReadGuard, AsyncRwLockWriteGuard};

/// Result type for concurrency operations
pub type ConcurrencyResult<T> = std::result::Result<T, ConcurrencyError>;

/// Error type for concurrency operations
#[derive(Debug, thiserror::Error)]
pub enum ConcurrencyError {
    #[error("Timeout occurred")]
    Timeout,
    
    #[error("Lock acquisition failed: {0}")]
    LockAcquisitionFailed(String),
    
    #[error("Mutex is poisoned")]
    PoisonedLock,
    
    #[error("Semaphore is closed")]
    SemaphoreClosed,
    
    #[error("Channel is closed")]
    ChannelClosed,
    
    #[error("Operation was canceled")]
    Canceled,
    
    #[error("Concurrency operation failed: {0}")]
    Other(String),
}

/// Extension trait for futures that adds a timeout
#[cfg(feature = "async")]
pub trait TimeoutExt: std::future::Future + Sized {
    /// Adds a timeout to a future
    fn timeout(self, duration: std::time::Duration) -> tokio::time::Timeout<Self> {
        tokio::time::timeout(duration, self)
    }
    
    /// Adds a deadline to a future
    fn deadline(self, deadline: std::time::Instant) -> tokio::time::Timeout<Self> {
        let duration = deadline.saturating_duration_since(std::time::Instant::now());
        tokio::time::timeout(duration, self)
    }
}

#[cfg(feature = "async")]
impl<F: std::future::Future> TimeoutExt for F {}

/// Runs a closure in a new thread with a timeout
pub fn run_with_timeout<F, T>(f: F, timeout: std::time::Duration) -> ConcurrencyResult<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    use std::sync::mpsc;
    use std::thread;
    
    let (tx, rx) = mpsc::channel();
    
    let handle = thread::spawn(move || {
        let result = f();
        let _ = tx.send(result);
    });
    
    match rx.recv_timeout(timeout) {
        Ok(result) => Ok(result),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // The thread is still running, but we don't need its result
            Err(ConcurrencyError::Timeout)
        },
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // The thread panicked or was terminated
            Err(ConcurrencyError::ChannelClosed)
        },
    }
}

/// Returns a future that completes after the specified duration
#[cfg(feature = "async")]
pub async fn sleep(duration: std::time::Duration) {
    tokio::time::sleep(duration).await
}

/// Returns a future that completes at the specified instant
#[cfg(feature = "async")]
pub async fn sleep_until(deadline: std::time::Instant) {
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_run_with_timeout_success() {
        let result = run_with_timeout(|| {
            thread::sleep(Duration::from_millis(10));
            42
        }, Duration::from_millis(100));
        
        assert_eq!(result.unwrap(), 42);
    }
    
    #[test]
    fn test_run_with_timeout_timeout() {
        let result = run_with_timeout(|| {
            thread::sleep(Duration::from_millis(100));
            42
        }, Duration::from_millis(10));
        
        assert!(matches!(result, Err(ConcurrencyError::Timeout)));
    }
    
    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_timeout_ext() {
        use std::time::Duration;
        
        // Test successful case
        let result = async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            42
        }
        .timeout(Duration::from_millis(100))
        .await;
        
        assert_eq!(result.unwrap(), 42);
        
        // Test timeout case
        let result = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            42
        }
        .timeout(Duration::from_millis(10))
        .await;
        
        assert!(result.is_err());
    }
}
