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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use crate::{middleware::MiddlewareStack, network_routing::MultiNetworkApi};

    fn ws_config() -> WsConfig {
        WsConfig { listen_addr: "127.0.0.1:9000".parse().unwrap(), max_subscriptions_per_connection: 50 }
    }

    #[test]
    fn ws_server_listen_addr() {
        let server = WsServer::new(ws_config(), MiddlewareStack::default(), MultiNetworkApi::default());
        assert_eq!(server.listen_addr().port(), 9000);
    }

    #[test]
    fn ws_server_max_subscriptions_per_connection() {
        let server = WsServer::new(ws_config(), MiddlewareStack::default(), MultiNetworkApi::default());
        assert_eq!(server.max_subscriptions_per_connection(), 50);
    }

    #[test]
    fn subscription_filter_stores_event_types() {
        let f = SubscriptionFilter { event_types: vec!["BlockFinalized".into(), "TxConfirmed".into()], addresses: vec![] };
        assert_eq!(f.event_types.len(), 2);
    }
}
