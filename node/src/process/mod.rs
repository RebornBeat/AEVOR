//! Process management: signal handling.

pub type SignalReceiver = tokio::sync::mpsc::Receiver<String>;

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
