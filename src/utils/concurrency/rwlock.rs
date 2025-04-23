use std::fmt;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::Notify;

use super::{ConcurrencyError, ConcurrencyResult};

/// An asynchronous reader-writer lock for shared read and exclusive write access
pub struct AsyncRwLock<T> {
    /// Inner reader-writer lock protecting the data
    inner: RwLock<T>,
    
    /// Notification for waiting read tasks
    read_notify: Arc<Notify>,
    
    /// Notification for waiting write tasks
    write_notify: Arc<Notify>,
}

impl<T> AsyncRwLock<T> {
    /// Creates a new asynchronous reader-writer lock
    pub fn new(value: T) -> Self {
        Self {
            inner: RwLock::new(value),
            read_notify: Arc::new(Notify),
            write_notify: Arc::new(Notify),
        }
    }
    
    /// Attempts to acquire a read lock without blocking
    pub fn try_read(&self) -> Option<AsyncRwLockReadGuard<'_, T>> {
        self.inner.try_read().map(|guard| {
            AsyncRwLockReadGuard {
                guard,
                read_notify: Arc::clone(&self.read_notify),
                write_notify: Arc::clone(&self.write_notify),
            }
        })
    }
    
    /// Asynchronously acquires a read lock
    pub async fn read(&self) -> AsyncRwLockReadGuard<'_, T> {
        // Try to lock immediately first
        if let Some(guard) = self.try_read() {
            return guard;
        }
        
        // Enter the async waiting path
        loop {
            // Set up the notification
            let notified = self.read_notify.notified();
            
            // Try again before waiting
            if let Some(guard) = self.try_read() {
                return guard;
            }
            
            // Wait for notification
            notified.await;
            
            // Try again after notification
            if let Some(guard) = self.try_read() {
                return guard;
            }
            
            // If we reach here, someone else got the lock before us
            // Loop and try again
        }
    }
    
    /// Asynchronously acquires a read lock with a timeout
    pub async fn read_timeout(&self, timeout: Duration) -> ConcurrencyResult<AsyncRwLockReadGuard<'_, T>> {
        // Try to lock immediately first
        if let Some(guard) = self.try_read() {
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
            let notified = self.read_notify.notified();
            
            // Try again before waiting
            if let Some(guard) = self.try_read() {
                return Ok(guard);
            }
            
            // Wait for notification with timeout
            let timeout_future = Box::pin(tokio::time::sleep(remaining));
            let notified_future = Box::pin(notified);
            
            match futures::future::select(notified_future, timeout_future).await {
                futures::future::Either::Left((_, _)) => {
                    // Notification received, try to acquire the lock
                    if let Some(guard) = self.try_read() {
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
    
    /// Attempts to acquire a write lock without blocking
    pub fn try_write(&self) -> Option<AsyncRwLockWriteGuard<'_, T>> {
        self.inner.try_write().map(|guard| {
            AsyncRwLockWriteGuard {
                guard,
                read_notify: Arc::clone(&self.read_notify),
                write_notify: Arc::clone(&self.write_notify),
            }
        })
    }
    
    /// Asynchronously acquires a write lock
    pub async fn write(&self) -> AsyncRwLockWriteGuard<'_, T> {
        // Try to lock immediately first
        if let Some(guard) = self.try_write() {
            return guard;
        }
        
        // Enter the async waiting path
        loop {
            // Set up the notification
            let notified = self.write_notify.notified();
            
            // Try again before waiting
            if let Some(guard) = self.try_write() {
                return guard;
            }
            
            // Wait for notification
            notified.await;
            
            // Try again after notification
            if let Some(guard) = self.try_write() {
                return guard;
            }
            
            // If we reach here, someone else got the lock before us
            // Loop and try again
        }
    }
    
    /// Asynchronously acquires a write lock with a timeout
    pub async fn write_timeout(&self, timeout: Duration) -> ConcurrencyResult<AsyncRwLockWriteGuard<'_, T>> {
        // Try to lock immediately first
        if let Some(guard) = self.try_write() {
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
            let notified = self.write_notify.notified();
            
            // Try again before waiting
            if let Some(guard) = self.try_write() {
                return Ok(guard);
            }
            
            // Wait for notification with timeout
            let timeout_future = Box::pin(tokio::time::sleep(remaining));
            let notified_future = Box::pin(notified);
            
            match futures::future::select(notified_future, timeout_future).await {
                futures::future::Either::Left((_, _)) => {
                    // Notification received, try to acquire the lock
                    if let Some(guard) = self.try_write() {
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
    
    /// Consumes the lock and returns the inner value
    pub fn into_inner(self) -> T {
        self.inner.into_inner()
    }
}

impl<T: Default> Default for AsyncRwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for AsyncRwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.inner.try_read() {
            Some(guard) => f.debug_struct("AsyncRwLock")
                .field("data", &*guard)
                .field("poisoned", &false)
                .finish(),
            None => f.debug_struct("AsyncRwLock")
                .field("data", &format_args!("<locked>"))
                .field("poisoned", &false)
                .finish(),
        }
    }
}

/// A guard that provides shared read access to the data protected by AsyncRwLock
pub struct AsyncRwLockReadGuard<'a, T> {
    /// The inner guard from parking_lot::RwLock
    guard: RwLockReadGuard<'a, T>,
    
    /// Notification for waiting read tasks
    read_notify: Arc<Notify>,
    
    /// Notification for waiting write tasks
    write_notify: Arc<Notify>,
}

impl<'a, T> Deref for AsyncRwLockReadGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &*self.guard
    }
}

impl<'a, T> Drop for AsyncRwLockReadGuard<'a, T> {
    fn drop(&mut self) {
        // On drop, notify both readers and writers
        // since either can proceed when a reader drops
        self.read_notify.notify_one();
        self.write_notify.notify_one();
    }
}

impl<'a, T: fmt::Debug> fmt::Debug for AsyncRwLockReadGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: fmt::Display> fmt::Display for AsyncRwLockReadGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

/// A guard that provides exclusive write access to the data protected by AsyncRwLock
pub struct AsyncRwLockWriteGuard<'a, T> {
    /// The inner guard from parking_lot::RwLock
    guard: RwLockWriteGuard<'a, T>,
    
    /// Notification for waiting read tasks
    read_notify: Arc<Notify>,
    
    /// Notification for waiting write tasks
    write_notify: Arc<Notify>,
}

impl<'a, T> Deref for AsyncRwLockWriteGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        &*self.guard
    }
}

impl<'a, T> DerefMut for AsyncRwLockWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.guard
    }
}

impl<'a, T> Drop for AsyncRwLockWriteGuard<'a, T> {
    fn drop(&mut self) {
        // On drop, notify all waiters since both readers and writers
        // can proceed when a writer drops
        // First notify all readers
        for _ in 0..10 {  // Notify several readers
            self.read_notify.notify_one();
        }
        // Then notify a writer
        self.write_notify.notify_one();
    }
}

impl<'a, T: fmt::Debug> fmt::Debug for AsyncRwLockWriteGuard<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<'a, T: fmt::Display> fmt::Display for AsyncRwLockWriteGuard<'a, T> {
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
    async fn test_async_rwlock_basic() {
        let rwlock = AsyncRwLock::new(0);
        
        // Acquire read lock
        {
            let guard = rwlock.read().await;
            assert_eq!(*guard, 0);
        }
        
        // Acquire write lock
        {
            let mut guard = rwlock.write().await;
            *guard += 1;
        }
        
        // Verify the value was updated
        {
            let guard = rwlock.read().await;
            assert_eq!(*guard, 1);
        }
    }
    
    #[tokio::test]
    async fn test_async_rwlock_multiple_readers() {
        let rwlock = Arc::new(AsyncRwLock::new(0));
        
        // Acquire multiple read locks concurrently
        let guard1_future = rwlock.read();
        let guard2_future = rwlock.read();
        
        let (guard1, guard2) = tokio::join!(guard1_future, guard2_future);
        
        // Both read locks should succeed
        assert_eq!(*guard1, 0);
        assert_eq!(*guard2, 0);
        
        // Drop one guard
        drop(guard1);
        
        // We should still be able to read the value
        assert_eq!(*guard2, 0);
        
        // Drop the second guard
        drop(guard2);
    }
    
    #[tokio::test]
    async fn test_async_rwlock_writer_blocks_readers() {
        let rwlock = Arc::new(AsyncRwLock::new(0));
        
        // Acquire write lock
        let write_guard = rwlock.write().await;
        
        // Try to acquire read lock (should not complete immediately)
        let rwlock_clone = Arc::clone(&rwlock);
        let read_task = tokio::spawn(async move {
            let guard = rwlock_clone.read_timeout(Duration::from_millis(10)).await;
            guard.is_err()  // Should timeout
        });
        
        // Wait for the read task to complete
        let read_timed_out = read_task.await.unwrap();
        assert!(read_timed_out, "Read should have timed out while write lock is held");
        
        // Release write lock
        drop(write_guard);
        
        // Now read should succeed
        let guard = rwlock.read().await;
        assert_eq!(*guard, 0);
    }
    
    #[tokio::test]
    async fn test_async_rwlock_readers_block_writer() {
        let rwlock = Arc::new(AsyncRwLock::new(0));
        
        // Acquire read lock
        let read_guard = rwlock.read().await;
        
        // Try to acquire write lock (should not complete immediately)
        let rwlock_clone = Arc::clone(&rwlock);
        let write_task = tokio::spawn(async move {
            let guard = rwlock_clone.write_timeout(Duration::from_millis(10)).await;
            guard.is_err()  // Should timeout
        });
        
        // Wait for the write task to complete
        let write_timed_out = write_task.await.unwrap();
        assert!(write_timed_out, "Write should have timed out while read lock is held");
        
        // Release read lock
        drop(read_guard);
        
        // Now write should succeed
        let mut guard = rwlock.write().await;
        *guard = 1;
        drop(guard);
        
        // Verify the value was updated
        let guard = rwlock.read().await;
        assert_eq!(*guard, 1);
    }
    
    #[tokio::test]
    async fn test_async_rwlock_write_to_read_downgrade() {
        let rwlock = AsyncRwLock::new(0);
        
        // Acquire write lock and modify
        {
            let mut guard = rwlock.write().await;
            *guard = 42;
            
            // We'd have to drop the write guard to downgrade
            // This isn't a direct downgrade, but it's the pattern you'd use
        }
        
        // Acquire read lock
        let guard = rwlock.read().await;
        assert_eq!(*guard, 42);
    }
    
    #[tokio::test]
    async fn test_async_rwlock_try_read_write() {
        let rwlock = AsyncRwLock::new(0);
        
        // Try read should succeed
        let read_guard = rwlock.try_read().unwrap();
        
        // Try write should fail while read lock is held
        assert!(rwlock.try_write().is_none());
        
        // Release read lock
        drop(read_guard);
        
        // Now try write should succeed
        let write_guard = rwlock.try_write().unwrap();
        
        // Try read should fail while write lock is held
        assert!(rwlock.try_read().is_none());
        
        // Release write lock
        drop(write_guard);
        
        // Now try read should succeed again
        assert!(rwlock.try_read().is_some());
    }
    
    #[tokio::test]
    async fn test_async_rwlock_contention() {
        let rwlock = Arc::new(AsyncRwLock::new(0));
        
        // Spawn multiple reader and writer tasks
        let handles = (0..5).map(|i| {
            let rwlock = Arc::clone(&rwlock);
            tokio::spawn(async move {
                for j in 0..10 {
                    if j % 2 == 0 {
                        // Even iterations: read
                        let guard = rwlock.read().await;
                        // Just read the value
                        let _ = *guard;
                        // Small delay to increase contention
                        tokio::time::sleep(Duration::from_micros(1)).await;
                    } else {
                        // Odd iterations: write
                        let mut guard = rwlock.write().await;
                        *guard += 1;
                        // Small delay to increase contention
                        tokio::time::sleep(Duration::from_micros(1)).await;
                    }
                }
                i
            })
        }).collect::<Vec<_>>();
        
        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }
        
        // Each task does 5 writes (odd iterations), 5 tasks total = 25 writes
        let guard = rwlock.read().await;
        assert_eq!(*guard, 25);
    }
    
    #[tokio::test]
    async fn test_async_rwlock_into_inner() {
        let rwlock = AsyncRwLock::new(42);
        assert_eq!(rwlock.into_inner(), 42);
    }
}
