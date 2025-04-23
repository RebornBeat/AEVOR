use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::Notify;
use std::collections::VecDeque;

use super::{ConcurrencyError, ConcurrencyResult};

/// An asynchronous semaphore for limiting concurrent access
pub struct AsyncSemaphore {
    /// Inner state protected by a mutex
    inner: Mutex<AsyncSemaphoreState>,
    
    /// Notification for waiting tasks
    notify: Arc<Notify>,
}

struct AsyncSemaphoreState {
    /// Maximum number of permits
    max_permits: usize,
    
    /// Current number of available permits
    available_permits: usize,
    
    /// Whether the semaphore is closed
    closed: bool,
}

impl AsyncSemaphore {
    /// Creates a new asynchronous semaphore with the specified number of permits
    pub fn new(permits: usize) -> Self {
        Self {
            inner: Mutex::new(AsyncSemaphoreState {
                max_permits: permits,
                available_permits: permits,
                closed: false,
            }),
            notify: Arc::new(Notify),
        }
    }
    
    /// Asynchronously acquires a permit
    pub async fn acquire(&self) -> ConcurrencyResult<AsyncSemaphorePermit> {
        // Try to acquire immediately first
        if let Some(permit) = self.try_acquire() {
            return Ok(permit);
        }
        
        // Enter the async waiting path
        loop {
            // Set up the notification
            let notified = self.notify.notified();
            
            // Check if semaphore is closed
            {
                let state = self.inner.lock();
                if state.closed {
                    return Err(ConcurrencyError::SemaphoreClosed);
                }
            }
            
            // Try again before waiting
            if let Some(permit) = self.try_acquire() {
                return Ok(permit);
            }
            
            // Wait for notification
            notified.await;
            
            // Try again after notification
            if let Some(permit) = self.try_acquire() {
                return Ok(permit);
            }
            
            // If we reach here, someone else got the permit before us
            // Loop and try again
        }
    }
    
    /// Asynchronously acquires a permit with a timeout
    pub async fn acquire_timeout(&self, timeout: Duration) -> ConcurrencyResult<AsyncSemaphorePermit> {
        // Try to acquire immediately first
        if let Some(permit) = self.try_acquire() {
            return Ok(permit);
        }
        
        // Set the deadline
        let deadline = Instant::now() + timeout;
        
        // Enter the async waiting path with timeout
        loop {
            // Compute remaining time
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ConcurrencyError::Timeout);
            }
            
            // Check if semaphore is closed
            {
                let state = self.inner.lock();
                if state.closed {
                    return Err(ConcurrencyError::SemaphoreClosed);
                }
            }
            
            // Set up the notification with timeout
            let notified = self.notify.notified();
            
            // Try again before waiting
            if let Some(permit) = self.try_acquire() {
                return Ok(permit);
            }
            
            // Wait for notification with timeout
            let timeout_future = Box::pin(tokio::time::sleep(remaining));
            let notified_future = Box::pin(notified);
            
            match futures::future::select(notified_future, timeout_future).await {
                futures::future::Either::Left((_, _)) => {
                    // Notification received, try to acquire the permit
                    if let Some(permit) = self.try_acquire() {
                        return Ok(permit);
                    }
                    // Someone else got the permit, loop and try again
                },
                futures::future::Either::Right((_, _)) => {
                    // Timeout occurred
                    return Err(ConcurrencyError::Timeout);
                }
            }
        }
    }
    
    /// Attempts to acquire a permit without blocking
    pub fn try_acquire(&self) -> Option<AsyncSemaphorePermit> {
        let mut state = self.inner.lock();
        
        if state.closed {
            return None;
        }
        
        if state.available_permits > 0 {
            state.available_permits -= 1;
            return Some(AsyncSemaphorePermit {
                semaphore: self,
                released: false,
            });
        }
        
        None
    }
    
    /// Releases a permit back to the semaphore
    fn release(&self) {
        let mut state = self.inner.lock();
        
        if state.closed {
            return;
        }
        
        state.available_permits = state.available_permits.saturating_add(1).min(state.max_permits);
        
        // Notify waiting tasks that a permit is available
        drop(state); // Release the lock before notification
        self.notify.notify_one();
    }
    
    /// Returns the number of currently available permits
    pub fn available_permits(&self) -> usize {
        let state = self.inner.lock();
        state.available_permits
    }
    
    /// Returns the maximum number of permits
    pub fn max_permits(&self) -> usize {
        let state = self.inner.lock();
        state.max_permits
    }
    
    /// Closes the semaphore, preventing new acquisitions
    pub fn close(&self) {
        let mut state = self.inner.lock();
        state.closed = true;
        
        // Notify all waiting tasks that the semaphore is closed
        drop(state); // Release the lock before notification
        self.notify.notify_waiters();
    }
    
    /// Returns whether the semaphore is closed
    pub fn is_closed(&self) -> bool {
        let state = self.inner.lock();
        state.closed
    }
    
    /// Adds more permits to the semaphore
    pub fn add_permits(&self, count: usize) {
        if count == 0 {
            return;
        }
        
        let mut state = self.inner.lock();
        
        if state.closed {
            return;
        }
        
        state.max_permits = state.max_permits.saturating_add(count);
        state.available_permits = state.available_permits.saturating_add(count);
        
        // Notify waiting tasks that permits are available
        drop(state); // Release the lock before notification
        
        // Notify multiple waiters based on the number of permits added
        for _ in 0..count {
            self.notify.notify_one();
        }
    }
}

impl fmt::Debug for AsyncSemaphore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.inner.lock();
        f.debug_struct("AsyncSemaphore")
            .field("max_permits", &state.max_permits)
            .field("available_permits", &state.available_permits)
            .field("closed", &state.closed)
            .finish()
    }
}

/// A permit that represents the right to perform an operation
pub struct AsyncSemaphorePermit<'a> {
    /// The semaphore this permit belongs to
    semaphore: &'a AsyncSemaphore,
    
    /// Whether the permit has been released
    released: bool,
}

impl<'a> AsyncSemaphorePermit<'a> {
    /// Releases the permit back to the semaphore
    pub fn release(mut self) {
        if !self.released {
            self.semaphore.release();
            self.released = true;
        }
    }
    
    /// Forgets the permit without releasing it back to the semaphore
    pub fn forget(mut self) {
        self.released = true;
    }
}

impl<'a> Drop for AsyncSemaphorePermit<'a> {
    fn drop(&mut self) {
        if !self.released {
            self.semaphore.release();
            self.released = true;
        }
    }
}

impl<'a> fmt::Debug for AsyncSemaphorePermit<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncSemaphorePermit")
            .field("released", &self.released)
            .finish()
    }
}

/// Utility to execute a guarded operation with a semaphore
pub async fn with_semaphore<T, F>(semaphore: &AsyncSemaphore, f: F) -> ConcurrencyResult<T>
where
    F: FnOnce() -> T,
{
    let permit = semaphore.acquire().await?;
    let result = f();
    permit.release();
    Ok(result)
}

/// Utility to execute an async guarded operation with a semaphore
pub async fn with_semaphore_async<T, F, Fut>(semaphore: &AsyncSemaphore, f: F) -> ConcurrencyResult<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let permit = semaphore.acquire().await?;
    let result = f().await;
    permit.release();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_async_semaphore_basic() {
        let semaphore = AsyncSemaphore::new(2);
        
        // Should be able to acquire 2 permits
        let permit1 = semaphore.acquire().await.unwrap();
        let permit2 = semaphore.acquire().await.unwrap();
        
        // A third acquire should wait
        let acquire_future = semaphore.acquire();
        
        // Release one permit
        permit1.release();
        
        // Now the third acquire should succeed
        let permit3 = acquire_future.await.unwrap();
        
        // Release remaining permits
        permit2.release();
        permit3.release();
    }
    
    #[tokio::test]
    async fn test_async_semaphore_try_acquire() {
        let semaphore = AsyncSemaphore::new(1);
        
        // First try_acquire should succeed
        let permit = semaphore.try_acquire().unwrap();
        
        // Second try_acquire should fail
        assert!(semaphore.try_acquire().is_none());
        
        // Release the permit
        permit.release();
        
        // Now try_acquire should succeed again
        assert!(semaphore.try_acquire().is_some());
    }
    
    #[tokio::test]
    async fn test_async_semaphore_timeout() {
        let semaphore = AsyncSemaphore::new(1);
        
        // Acquire the only permit
        let permit = semaphore.acquire().await.unwrap();
        
        // Trying to acquire with a timeout should fail
        let result = semaphore.acquire_timeout(Duration::from_millis(10)).await;
        assert!(matches!(result, Err(ConcurrencyError::Timeout)));
        
        // Release the permit
        permit.release();
        
        // Now acquisition should succeed
        let result = semaphore.acquire_timeout(Duration::from_millis(10)).await;
        assert!(result.is_ok());
        result.unwrap().release();
    }
    
    #[tokio::test]
    async fn test_async_semaphore_close() {
        let semaphore = AsyncSemaphore::new(1);
        
        // Close the semaphore
        semaphore.close();
        
        // Acquire should now fail
        let result = semaphore.acquire().await;
        assert!(matches!(result, Err(ConcurrencyError::SemaphoreClosed)));
        
        // Try_acquire should also fail
        assert!(semaphore.try_acquire().is_none());
    }
    
    #[tokio::test]
    async fn test_async_semaphore_with_semaphore() {
        let semaphore = AsyncSemaphore::new(1);
        
        // Execute a function with the semaphore
        let result = with_semaphore(&semaphore, || 42).await;
        assert_eq!(result.unwrap(), 42);
        
        // Execute an async function with the semaphore
        let result = with_semaphore_async(&semaphore, || async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            43
        }).await;
        assert_eq!(result.unwrap(), 43);
    }
    
    #[tokio::test]
    async fn test_async_semaphore_contention() {
        let semaphore = Arc::new(AsyncSemaphore::new(3));
        let counter = Arc::new(parking_lot::Mutex::new(0));
        
        // Launch 10 tasks that all try to acquire the semaphore
        let handles = (0..10).map(|_| {
            let semaphore = Arc::clone(&semaphore);
            let counter = Arc::clone(&counter);
            
            tokio::spawn(async move {
                // Acquire the semaphore
                let permit = semaphore.acquire().await.unwrap();
                
                // Increment the counter (limited to 3 at a time)
                {
                    let mut counter = counter.lock();
                    *counter += 1;
                    assert!(*counter <= 3);
                    
                    // Sleep to increase contention
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    
                    *counter -= 1;
                }
                
                // Release the permit
                permit.release();
            })
        }).collect::<Vec<_>>();
        
        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }
        
        // Verify the final counter is 0
        let counter = counter.lock();
        assert_eq!(*counter, 0);
    }
    
    #[tokio::test]
    async fn test_async_semaphore_add_permits() {
        let semaphore = AsyncSemaphore::new(0);
        
        // With 0 permits, acquire should wait
        let acquire_future = semaphore.acquire();
        
        // Add a permit
        semaphore.add_permits(1);
        
        // Now the acquire should succeed
        let permit = acquire_future.await.unwrap();
        permit.release();
        
        // Add multiple permits
        semaphore.add_permits(3);
        assert_eq!(semaphore.available_permits(), 4);
        
        // Multiple acquires should succeed
        let permit1 = semaphore.acquire().await.unwrap();
        let permit2 = semaphore.acquire().await.unwrap();
        let permit3 = semaphore.acquire().await.unwrap();
        let permit4 = semaphore.acquire().await.unwrap();
        
        // A fifth acquire should wait
        let acquire_future = semaphore.acquire();
        
        // Release the permits
        permit1.release();
        permit2.release();
        permit3.release();
        permit4.release();
        
        // The waiting acquire should succeed
        let permit5 = acquire_future.await.unwrap();
        permit5.release();
    }
    
    #[tokio::test]
    async fn test_async_semaphore_forget() {
        let semaphore = AsyncSemaphore::new(1);
        
        // Acquire and forget the permit
        let permit = semaphore.acquire().await.unwrap();
        permit.forget();
        
        // The semaphore should now have 0 permits
        assert_eq!(semaphore.available_permits(), 0);
        
        // Adding a permit should make it available again
        semaphore.add_permits(1);
        
        // Now an acquisition should succeed
        let permit = semaphore.acquire().await.unwrap();
        permit.release();
    }
}
