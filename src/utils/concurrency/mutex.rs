use std::fmt;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use parking_lot::{Mutex, MutexGuard};
use tokio::sync::Notify;

use super::{ConcurrencyError, ConcurrencyResult};

/// An asynchronous mutex for exclusive access to data
pub struct AsyncMutex<T> {
    /// Inner mutex protecting the data
    inner: Mutex<T>,
    
    /// Notification for waiting tasks
    notify: Arc<Notify>,
}

impl<T> AsyncMutex<T> {
    /// Creates a new asynchronous mutex
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            notify: Arc::new(Notify),
        }
    }
    
    /// Attempts to acquire the lock without blocking
    pub fn try_lock(&self) -> Option<AsyncMutexGuard<'_, T>> {
        self.inner.try_lock().map(|guard| {
            AsyncMutexGuard {
                guard,
                notify: Arc::clone(&self.notify),
            }
        })
    }
    
    /// Asynchronously acquires the lock
    pub async fn lock(&self) -> AsyncMutexGuard<'_, T> {
        // Try to lock immediately first
        if let Some(guard) = self.try_lock() {
            return guard;
        }
        
        // Enter the async waiting path
        loop {
            // Set up the notification
            let notified = self.notify.notified();
            
            // Try again before waiting
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            
            // Wait for notification
            notified.await;
            
            // Try again after notification
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            
            // If we reach here, someone else got the lock before us
            // Loop and try again
        }
    }
    
    /// Asynchronously acquires the lock with a timeout
    pub async fn lock_timeout(&self, timeout: Duration) -> ConcurrencyResult<AsyncMutexGuard<'_, T>> {
        // Try to lock immediately first
        if let Some(guard) = self.try_lock() {
            return Ok(guard);
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
            
            // Set up the notification with timeout
            let notified = self.notify.notified();
            
            // Try again before waiting
            if let Some(guard) = self.try_lock() {
                return Ok(guard);
            }
            
            // Wait for notification with timeout
            let timeout_future = Box::pin(tokio::time::sleep(remaining));
            let notified_future = Box::pin(notified);
            
            match futures::future::select(notified_future, timeout_future).await {
                futures::future::Either::Left((_, _)) => {
                    // Notification received, try to acquire the lock
                    if let Some(guard) = self.try_lock() {
                        return Ok(guard);
                    }
                    // Someone else got the lock, loop and try again
                },
                futures::future::Either::Right((_, _)) => {
                    // Timeout occurred
                    return Err(ConcurrencyError::Timeout);
                }
            }
        }
    }
    
    /// Gets an immutable reference to the inner value without locking
    /// 
    /// # Safety
    /// 
    /// This is unsafe because it allows accessing the inner value without acquiring the lock.
    /// The caller must ensure that no other thread is currently accessing the inner value.
    pub unsafe fn get_unchecked(&self) -> &T {
        self.inner.data_ptr()
    }
    
    /// Consumes the mutex and returns the inner value
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: Default> Default for AsyncMutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for AsyncMutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.try_lock() {
            Some(guard) => f.debug_struct("AsyncMutex")
                .field("data", &*guard)
                .field("poisoned", &false)
                .finish(),
            None => f.debug_struct("AsyncMutex")
                .field("data", &format_args!("<locked>"))
                .field("poisoned", &false)
                .finish(),
        }
    }
}

/// A guard that provides exclusive access to the data protected by AsyncMutex
pub struct AsyncMutexGuard<'a, T> {
    /// The inner guard from parking_lot::Mutex
    guard: MutexGuard<'a, T>,
    
    /// Notification for waiting tasks
    notify: Arc<Notify>,
}

impl<'a, T> Deref for AsyncMutexGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &*self.guard
    }
}

impl<'a, T> DerefMut for AsyncMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.guard
    }
}

impl<'a, T> Drop for AsyncMutexGuard<'a, T> {
    fn drop(&mut self) {
        // Notify one waiting task that the lock is available
        self.notify.notify_one();
    }
}

impl<'a, T: fmt::Debug> fmt::Debug for AsyncMutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: fmt::Display> fmt::Display for AsyncMutexGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_async_mutex_basic() {
        let mutex = AsyncMutex::new(0);
        
        {
            let mut guard = mutex.lock().await;
            *guard += 1;
        }
        
        {
            let guard = mutex.lock().await;
            assert_eq!(*guard, 1);
        }
    }
    
    #[tokio::test]
    async fn test_async_mutex_contention() {
        let mutex = Arc::new(AsyncMutex::new(0));
        let handles = (0..10).map(|_| {
            let mutex = Arc::clone(&mutex);
            tokio::spawn(async move {
                for _ in 0..100 {
                    let mut guard = mutex.lock().await;
                    *guard += 1;
                    // Add a small delay to increase contention
                    tokio::time::sleep(Duration::from_micros(1)).await;
                }
            })
        }).collect::<Vec<_>>();
        
        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }
        
        let guard = mutex.lock().await;
        assert_eq!(*guard, 1000);
    }
    
    #[tokio::test]
    async fn test_async_mutex_try_lock() {
        let mutex = AsyncMutex::new(0);
        
        {
            let mut guard = mutex.try_lock().unwrap();
            *guard += 1;
            
            // Should fail when the mutex is already locked
            assert!(mutex.try_lock().is_none());
        }
        
        // Should succeed after guard is dropped
        let guard = mutex.try_lock().unwrap();
        assert_eq!(*guard, 1);
    }
    
    #[tokio::test]
    async fn test_async_mutex_timeout() {
        let mutex = AsyncMutex::new(0);
        
        // Lock the mutex
        let guard = mutex.lock().await;
        
        // Try to lock with a timeout (should fail)
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            mutex.lock_timeout(Duration::from_millis(10))
        ).await;
        
        // Should be an error (timeout)
        assert!(result.unwrap().is_err());
        
        // Drop the guard to release the lock
        drop(guard);
        
        // Should succeed now
        let result = mutex.lock_timeout(Duration::from_millis(10)).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_async_mutex_default() {
        let mutex = AsyncMutex::<i32>::default();
        let guard = mutex.lock().await;
        assert_eq!(*guard, 0);
    }
    
    #[tokio::test]
    async fn test_async_mutex_into_inner() {
        let mutex = AsyncMutex::new(42);
        assert_eq!(mutex.into_inner(), 42);
    }
}
