//! WebSocket API server for live feeds.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct WsConfig { pub listen_addr: SocketAddr, pub max_subscriptions_per_connection: usize }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubscriptionFilter { pub event_types: Vec<String>, pub addresses: Vec<String> }
pub struct Subscription { pub id: String, pub filter: SubscriptionFilter }
pub struct EventStream;
pub struct LiveFeed;

pub struct WsServer { config: WsConfig }
impl WsServer {
    pub fn new(config: WsConfig, _middleware: crate::middleware::MiddlewareStack, _router: crate::network_routing::MultiNetworkApi) -> Self { Self { config } }
    pub async fn serve(&self) -> crate::ApiResult<()> { Ok(()) }
}
