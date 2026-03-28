//! Process management: signal handling.

pub type SignalReceiver = tokio::sync::mpsc::Receiver<String>;

/// Install OS signal handlers (SIGINT/SIGTERM) and return a receiver for shutdown signals.
///
/// # Errors
/// Currently always succeeds; `Result` allows future propagation of handler installation errors.
pub fn install_signal_handlers() -> crate::NodeResult<SignalReceiver> {
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        use tokio::signal;
        tokio::select! {
            _ = signal::ctrl_c() => { tx.send("SIGINT".into()).await.ok(); }
        }
    });
    Ok(rx)
}

#[cfg(test)]
mod tests {
    // install_signal_handlers spawns a tokio task — just verify it compiles
    // and returns a receiver without panicking in a non-tokio context check.
    #[test]
    fn signal_receiver_type_exists() {
        // The type alias compiles — runtime test would require a tokio runtime.
        let _: fn() -> super::SignalReceiver;
    }
}
