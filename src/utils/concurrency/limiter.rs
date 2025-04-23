use std::fmt;
use std::future::Future;
use std::sync::Arc;

use super::{AsyncSemaphore, AsyncSemaphorePermit, ConcurrencyResult};

/// A utility for limiting concurrency to a fixed number of tasks
pub struct ConcurrencyLimiter {
    /// The underlying semaphore
    semaphore: Arc<AsyncSemaphore>,
    
    /// The name of this limiter (for debugging)
    name: String,
}

impl ConcurrencyLimiter {
    /// Creates a new concurrency limiter with the specified limit
    pub fn new(limit: usize) -> Self {
        Self::with_name(limit, "unnamed")
    }
    
    /// Creates a new concurrency limiter with a name for debugging
    pub fn with_name(limit: usize, name: impl Into<String>) -> Self {
        Self {
            semaphore: Arc::new(AsyncSemaphore::new(limit)),
            name: name.into(),
        }
    }
    
    /// Returns the maximum number of concurrent tasks
    pub fn limit(&self) -> usize {
        self.semaphore.max_permits()
    }
    
    /// Returns the number of available execution slots
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }
    
    /// Returns the number of tasks currently executing
    pub fn active(&self) -> usize {
        self.limit() - self.available()
    }
    
    /// Asynchronously executes a task with limited concurrency
    pub async fn execute<F, T>(&self, task: F) -> ConcurrencyResult<T>
    where
        F: Future<Output = T>,
    {
        // Acquire a permit
        let permit = self.semaphore.acquire().await?;
        
        // Execute the task
        let result = task.await;
        
        // Release the permit
        permit.release();
        
        Ok(result)
    }
    
    /// Creates a clone of this limiter that refers to the same underlying semaphore
    pub fn clone(&self) -> Self {
        Self {
            semaphore: Arc::clone(&self.semaphore),
            name: self.name.clone(),
        }
    }
    
    /// Changes the limit
    pub fn set_limit(&self, new_limit: usize) {
        let current_limit = self.limit();
        if new_limit > current_limit {
            // Add permits
            self.semaphore.add_permits(new_limit - current_limit);
        } else if new_limit < current_limit {
            // We can't remove permits - they'll just not be replaced when released
            // The actual limit will decrease as tasks complete
            // TODO: Implement a way to reduce permits
        }
    }
    
    /// Acquires a permit directly
    pub async fn acquire(&self) -> ConcurrencyResult<AsyncSemaphorePermit> {
        self.semaphore.acquire().await
    }
    
    /// Tries to acquire a permit without waiting
    pub fn try_acquire(&self) -> Option<AsyncSemaphorePermit> {
        self.semaphore.try_acquire()
    }
    
    /// Gets the name of this limiter
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for ConcurrencyLimiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConcurrencyLimiter")
            .field("name", &self.name)
            .field("limit", &self.limit())
            .field("active", &self.active())
            .field("available", &self.available())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::{self, FutureExt};
    use std::sync::Arc;
    use std::time::Duration;
    
    #[tokio::test]
    async fn test_concurrency_limiter_basic() {
        let limiter = ConcurrencyLimiter::new(2);
        
        // Initially all slots available
        assert_eq!(limiter.limit(), 2);
        assert_eq!(limiter.available(), 2);
        assert_eq!(limiter.active(), 0);
        
        // Execute a task that takes some time
        let task1 = limiter.execute(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            1
        });
        
        // Limiter should have one active task
        assert_eq!(limiter.available(), 1);
        assert_eq!(limiter.active(), 1);
        
        // Execute another task
        let task2 = limiter.execute(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            2
        });
        
        // Limiter should be at capacity
        assert_eq!(limiter.available(), 0);
        assert_eq!(limiter.active(), 2);
        
        // Wait for tasks to complete
        let (result1, result2) = future::join(task1, task2).await;
        
        // Both tasks should succeed
        assert_eq!(result1.unwrap(), 1);
        assert_eq!(result2.unwrap(), 2);
        
        // Limiter should be back to full availability
        assert_eq!(limiter.available(), 2);
        assert_eq!(limiter.active(), 0);
    }
    
    #[tokio::test]
    async fn test_concurrency_limiter_blocking() {
        let limiter = ConcurrencyLimiter::new(1);
        
        // Execute a task that takes some time
        let task1 = tokio::spawn(async {
            let permit = limiter.acquire().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            permit.release();
            1
        });
        
        // Wait a bit for the task to start
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Limiter should be at capacity
        assert_eq!(limiter.available(), 0);
        
        // Try to execute another task (should be blocked)
        let start = std::time::Instant::now();
        let result = limiter.execute(async { 2 }).await.unwrap();
        let elapsed = start.elapsed();
        
        // Task should have been blocked until the first one completed
        assert!(elapsed >= Duration::from_millis(90), "Task was not blocked");
        assert_eq!(result, 2);
        
        // Limiter should be back to full availability
        assert_eq!(limiter.available(), 1);
        
        // Wait for first task
        assert_eq!(task1.await.unwrap(), 1);
    }
    
    #[tokio::test]
    async fn test_concurrency_limiter_clone() {
        let limiter1 = ConcurrencyLimiter::new(2);
        let limiter2 = limiter1.clone();
        
        // Both limiters should have the same limit
        assert_eq!(limiter1.limit(), 2);
        assert_eq!(limiter2.limit(), 2);
        
        // Acquire through one limiter
        let permit = limiter1.acquire().await.unwrap();
        
        // Should affect both limiters
        assert_eq!(limiter1.available(), 1);
        assert_eq!(limiter2.available(), 1);
        
        // Release the permit
        permit.release();
        
        // Both limiters should be back to full availability
        assert_eq!(limiter1.available(), 2);
        assert_eq!(limiter2.available(), 2);
    }
    
    #[tokio::test]
    async fn test_concurrency_limiter_set_limit() {
        let limiter = ConcurrencyLimiter::new(2);
        assert_eq!(limiter.limit(), 2);
        
        // Acquire one permit
        let permit = limiter.acquire().await.unwrap();
        assert_eq!(limiter.available(), 1);
        assert_eq!(limiter.active(), 1);
        
        // Increase the limit
        limiter.set_limit(4);
        assert_eq!(limiter.limit(), 4);
        assert_eq!(limiter.available(), 3);
        assert_eq!(limiter.active(), 1);
        
        // Release the permit
        permit.release();
        assert_eq!(limiter.available(), 4);
        assert_eq!(limiter.active(), 0);
    }
    
    #[tokio::test]
    async fn test_concurrency_limiter_with_name() {
        let limiter = ConcurrencyLimiter::with_name(2, "test-limiter");
        assert_eq!(limiter.name(), "test-limiter");
        assert_eq!(limiter.limit(), 2);
    }
}
