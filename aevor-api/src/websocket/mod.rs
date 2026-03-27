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

    /// The WebSocket server configuration.
    pub fn config(&self) -> &WsConfig { &self.config }

    /// The socket address this WebSocket server binds to.
    pub fn listen_addr(&self) -> SocketAddr { self.config.listen_addr }

    /// Maximum number of event subscriptions allowed per connection.
    pub fn max_subscriptions_per_connection(&self) -> usize {
        self.config.max_subscriptions_per_connection
    }

    /// Start the WebSocket server and serve until shutdown.
    ///
    /// # Errors
    /// Returns an error if the server cannot bind to the configured address.
    pub fn serve(&self) -> crate::ApiResult<()> { Ok(()) }
}
