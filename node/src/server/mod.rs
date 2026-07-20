//! Node-side request/response server.
//!
//! [`NodeServer`] listens on TCP and serves client [`NodeRequest`]s against a
//! shared [`NodeEngine`], returning [`NodeResponse`]s. It is the server end of
//! the same wire protocol `aevor_client::transport::TcpNodeConnection` speaks,
//! so a remote client and an in-process `EngineConnection` drive identical
//! engine logic. The engine is shared behind a mutex; each request is handled
//! under a short lock.

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex, PoisonError};

use aevor_client::exec::SubmitResponse;
use aevor_client::transport::{read_frame, write_frame, NodeRequest, NodeResponse};

use crate::engine::NodeEngine;

/// A TCP server exposing a [`NodeEngine`] to remote clients.
pub struct NodeServer;

impl NodeServer {
    /// Bind a server to `addr` (use port 0 to let the OS choose) serving the
    /// given engine, and spawn its accept loop. Returns the bound address.
    ///
    /// # Errors
    /// Returns an I/O error if the listener cannot bind.
    pub fn bind(
        engine: Arc<Mutex<NodeEngine>>,
        addr: SocketAddr,
    ) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Ok(request_bytes) = read_frame(&mut stream) else { continue };
                let Ok(request) = bincode::deserialize::<NodeRequest>(&request_bytes) else {
                    continue;
                };
                let response = {
                    let mut engine = engine.lock().unwrap_or_else(PoisonError::into_inner);
                    Self::process(&mut engine, request)
                };
                if let Ok(response_bytes) = bincode::serialize(&response) {
                    let _ = write_frame(&mut stream, &response_bytes);
                }
            }
        });
        Ok(local_addr)
    }

    /// Handle a single request against the engine — the same logic the
    /// in-process `EngineConnection` runs.
    fn process(engine: &mut NodeEngine, request: NodeRequest) -> NodeResponse {
        match request {
            NodeRequest::Submit(tx) => {
                let admitted = engine.submit(tx.clone());
                NodeResponse::Submit(SubmitResponse {
                    admitted,
                    tx_hash: tx.hash(),
                })
            }
            NodeRequest::Query(id) => match engine.prove_object(&id) {
                Ok(Some(proof)) if proof.is_inclusion => NodeResponse::Query(Some(proof)),
                Ok(_) => NodeResponse::Query(None),
                Err(e) => NodeResponse::Error(e.to_string()),
            },
        }
    }
}
