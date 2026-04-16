//! Lark WebSocket Implementation based on official Python SDK
//!
//! Reference: lark-oapi Python SDK ws/client.py
//! Protocol: Protobuf-based WebSocket frames

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::communication::channel::ChannelEvent;
use crate::communication::{Message, MessageType as CommMessageType, PlatformType};
use crate::error::{AgentError, Result};

/// Access token with expiration
#[derive(Debug, Clone)]
struct AccessToken {
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

impl AccessToken {
    /// Check if token is still valid (with 5 minute buffer)
    fn is_valid(&self) -> bool {
        let buffer = chrono::Duration::minutes(5);
        chrono::Utc::now() + buffer < self.expires_at
    }
}

// Feishu/Lark API endpoints
const FEISHU_DOMAIN: &str = "https://open.feishu.cn";
const GEN_ENDPOINT_URI: &str = "/callback/ws/endpoint";

// Error codes (from Python SDK const.py)
const OK: i32 = 0;
const _SYSTEM_BUSY: i32 = 1;
const FORBIDDEN: i32 = 403;
const AUTH_FAILED: i32 = 514;
const _INTERNAL_ERROR: i64 = 1000040343;
const _NO_CREDENTIAL: i64 = 1000040344;
const _EXCEED_CONN_LIMIT: i64 = 1000040350;

// Header keys (from Python SDK const.py)
const HEADER_TYPE: &str = "type";
const HEADER_MESSAGE_ID: &str = "message_id";
const HEADER_SUM: &str = "sum";
const HEADER_SEQ: &str = "seq";
const HEADER_TRACE_ID: &str = "trace_id";
const HEADER_BIZ_RT: &str = "biz_rt";
#[allow(dead_code)]
const HEADER_HANDSHAKE_STATUS: &str = "handshake-status";
#[allow(dead_code)]
const HEADER_HANDSHAKE_MSG: &str = "handshake-msg";
#[allow(dead_code)]
const HEADER_HANDSHAKE_AUTH_ERRCODE: &str = "handshake-autherrcode";

// Frame types (from Python SDK enum.py)
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(i32)]
enum FrameType {
    Control = 0,
    Data = 1,
}

// Message types (from Python SDK enum.py)
#[derive(Debug, Clone, PartialEq)]
enum MessageType {
    Event,
    Card,
    Ping,
    Pong,
}

impl MessageType {
    fn as_str(&self) -> &'static str {
        match self {
            MessageType::Event => "event",
            MessageType::Card => "card",
            MessageType::Ping => "ping",
            MessageType::Pong => "pong",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "event" => Some(MessageType::Event),
            "card" => Some(MessageType::Card),
            "ping" => Some(MessageType::Ping),
            "pong" => Some(MessageType::Pong),
            _ => None,
        }
    }
}

/// WebSocket endpoint response
#[derive(Debug, Deserialize)]
struct EndpointResp {
    code: i32,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    data: Option<Endpoint>,
}

#[derive(Debug, Deserialize)]
struct Endpoint {
    #[serde(rename = "URL")]
    url: String,
    #[serde(rename = "ClientConfig", default)]
    client_config: Option<ClientConfig>,
}

#[derive(Debug, Deserialize, Clone)]
struct ClientConfig {
    #[serde(rename = "PingInterval", default)]
    ping_interval: Option<u64>,
    #[serde(rename = "ReconnectCount", default)]
    _reconnect_count: Option<i32>,
    #[serde(rename = "ReconnectInterval", default)]
    _reconnect_interval: Option<u64>,
    #[serde(rename = "ReconnectNonce", default)]
    _reconnect_nonce: Option<u64>,
}

/// Protobuf Frame definition (from pbbp2.proto)
#[derive(Clone, PartialEq, prost::Message)]
struct Frame {
    #[prost(uint64, required, tag = "1")]
    seq_id: u64,
    #[prost(uint64, required, tag = "2")]
    log_id: u64,
    #[prost(int32, required, tag = "3")]
    service: i32,
    #[prost(int32, required, tag = "4")]
    method: i32,
    #[prost(message, repeated, tag = "5")]
    headers: Vec<Header>,
    #[prost(string, optional, tag = "6")]
    payload_encoding: Option<String>,
    #[prost(string, optional, tag = "7")]
    payload_type: Option<String>,
    #[prost(bytes, optional, tag = "8")]
    payload: Option<Vec<u8>>,
    #[prost(string, optional, tag = "9")]
    log_id_new: Option<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Header {
    #[prost(string, required, tag = "1")]
    key: String,
    #[prost(string, required, tag = "2")]
    value: String,
}

/// Response for event handling
#[derive(Debug, Serialize)]
struct Response {
    code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

/// Lark WebSocket client
pub struct LarkWebSocketClient {
    app_id: String,
    app_secret: String,
    http_client: reqwest::Client,
    connected: AtomicBool,
    shutdown: Arc<AtomicBool>,
    /// Cached access token for API calls
    access_token: Arc<RwLock<Option<AccessToken>>>,
    // Config from server
    _reconnect_count: AtomicBool, // Using as Option<i32> would need Mutex
    _reconnect_interval: AtomicBool,
    _reconnect_nonce: AtomicBool,
    _ping_interval: AtomicBool,
}

impl LarkWebSocketClient {
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self {
            app_id,
            app_secret,
            http_client: reqwest::Client::new(),
            connected: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            access_token: Arc::new(RwLock::new(None)),
            _reconnect_count: AtomicBool::new(false),
            _reconnect_interval: AtomicBool::new(false),
            _reconnect_nonce: AtomicBool::new(false),
            _ping_interval: AtomicBool::new(false),
        }
    }

    /// Get or refresh access token
    async fn get_access_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let token_guard = self.access_token.read().await;
            if let Some(token) = token_guard.as_ref() {
                if token.is_valid() {
                    return Ok(token.token.clone());
                }
            }
        }

        // Need to fetch a new token
        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            FEISHU_DOMAIN
        );

        info!("Fetching new access token from Feishu");

        let response = self
            .http_client
            .post(&url)
            .json(&serde_json::json!({
                "app_id": self.app_id,
                "app_secret": self.app_secret,
            }))
            .send()
            .await
            .map_err(|e| AgentError::platform(format!("Failed to get access token: {}", e)))?;

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AgentError::platform(format!("Failed to parse token response: {}", e)))?;

        let token_str = data["tenant_access_token"].as_str().ok_or_else(|| {
            AgentError::platform("Invalid token response: missing tenant_access_token")
        })?;

        let expires_in = data["expire"].as_i64().unwrap_or(7200); // Default 2 hours

        let token = AccessToken {
            token: token_str.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(expires_in),
        };

        // Cache the token
        let mut token_guard = self.access_token.write().await;
        *token_guard = Some(token);

        info!("Access token obtained, expires in {} seconds", expires_in);
        Ok(token_str.to_string())
    }

    /// Download image from Feishu using message_id and image_key (as file_key)
    ///
    /// Uses the message resource API:
    /// /open-apis/im/v1/messages/{message_id}/resources/{file_key}?type=image
    /// This API can download resources from received messages (unlike
    /// /im/v1/images which only works for uploaded images)
    ///
    /// Note: The `type` query parameter is required. Use "image" for images,
    /// "file" for other files.
    pub async fn download_image(&self, message_id: &str, file_key: &str) -> Result<Vec<u8>> {
        let token = self.get_access_token().await?;

        // IMPORTANT: The `type` query parameter is required by Feishu API
        let url = format!(
            "{}/open-apis/im/v1/messages/{}/resources/{}?type=image",
            FEISHU_DOMAIN, message_id, file_key
        );

        info!(
            "Downloading image from Feishu: message_id={}, file_key={}",
            message_id, file_key
        );

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AgentError::platform(format!("Failed to download image: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AgentError::platform(format!(
                "Image download failed: HTTP {} - {}",
                status, error_text
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| AgentError::platform(format!("Failed to read image bytes: {}", e)))?;

        info!("Downloaded image: {} bytes", bytes.len());
        Ok(bytes.to_vec())
    }

    /// Get WebSocket connection URL from Feishu server
    ///
    /// Based on Python SDK client.py:_get_conn_url()
    async fn get_ws_endpoint(&self) -> Result<(String, ClientConfig)> {
        let url = format!("{}{}", FEISHU_DOMAIN, GEN_ENDPOINT_URI);

        info!("Requesting WebSocket endpoint from: {}", url);

        let response = self
            .http_client
            .post(&url)
            .header("locale", "zh")
            .json(&serde_json::json!({
                "AppID": self.app_id,
                "AppSecret": self.app_secret,
            }))
            .send()
            .await
            .map_err(|e| AgentError::platform(format!("Failed to get endpoint: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| AgentError::platform(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            return Err(AgentError::platform(format!(
                "Endpoint request failed: HTTP {} - {}",
                status, body
            )));
        }

        let resp: EndpointResp = serde_json::from_str(&body).map_err(|e| {
            AgentError::platform(format!("Failed to parse endpoint response: {}", e))
        })?;

        match resp.code {
            OK => {}
            FORBIDDEN => {
                return Err(AgentError::platform(format!(
                    "Access forbidden: {}",
                    resp.msg.unwrap_or_default()
                )));
            }
            AUTH_FAILED => {
                return Err(AgentError::authentication(format!(
                    "Authentication failed: {}",
                    resp.msg.unwrap_or_default()
                )));
            }
            _ => {
                return Err(AgentError::platform(format!(
                    "Endpoint request failed: code={}, msg={:?}",
                    resp.code, resp.msg
                )));
            }
        }

        let data = resp
            .data
            .ok_or_else(|| AgentError::platform("No data in endpoint response"))?;

        info!("Got WebSocket URL: {}", data.url);

        let config = data.client_config.unwrap_or_else(|| ClientConfig {
            ping_interval: Some(120),
            _reconnect_count: Some(-1),
            _reconnect_interval: Some(120),
            _reconnect_nonce: Some(30),
        });

        Ok((data.url, config))
    }

    /// Connect and run event loop
    pub async fn connect(&self, event_tx: mpsc::Sender<ChannelEvent>) -> Result<()> {
        let (ws_url, client_config) = self.get_ws_endpoint().await?;

        info!("Connecting to Lark WebSocket: {}", ws_url);

        // Parse URL to extract device_id and service_id for logging
        let parsed_url = Url::parse(&ws_url)
            .map_err(|e| AgentError::platform(format!("Invalid WebSocket URL: {}", e)))?;

        let device_id = parsed_url
            .query_pairs()
            .find(|(k, _)| k == "device_id")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();

        let service_id = parsed_url
            .query_pairs()
            .find(|(k, _)| k == "service_id")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();

        let (ws_stream, _) = connect_async(&ws_url)
            .await
            .map_err(|e| AgentError::platform(format!("WebSocket connection failed: {}", e)))?;

        info!(
            "Lark WebSocket connected [device_id={}, service_id={}]",
            device_id, service_id
        );
        self.connected.store(true, Ordering::SeqCst);

        // Split stream
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        let ping_interval = client_config.ping_interval.unwrap_or(120);
        let mut ping_timer = interval(Duration::from_secs(ping_interval));
        let shutdown = self.shutdown.clone();

        loop {
            tokio::select! {
                _ = ping_timer.tick() => {
                    if let Err(e) = self.send_ping(&mut ws_sender, &service_id).await {
                        error!("Failed to send ping: {}", e);
                        break;
                    }
                }
                Some(msg) = ws_receiver.next() => {
                    match msg {
                        Ok(WsMessage::Binary(data)) => {
                            if let Err(e) = self.handle_frame(&data, &event_tx, &mut ws_sender).await {
                                warn!("Failed to handle frame: {}", e);
                            }
                        }
                        Ok(WsMessage::Text(text)) => {
                            // Sometimes server may send text for errors
                            warn!("Received text message: {}", text);
                        }
                        Ok(WsMessage::Close(frame)) => {
                            info!("WebSocket closed by server: {:?}", frame);
                            break;
                        }
                        Ok(WsMessage::Ping(data)) => {
                            if let Err(e) = ws_sender.send(WsMessage::Pong(data)).await {
                                error!("Failed to send pong: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    if shutdown.load(Ordering::SeqCst) {
                        info!("Shutdown signal received");
                        break;
                    }
                }
            }
        }

        self.connected.store(false, Ordering::SeqCst);
        info!("Lark WebSocket disconnected");
        Ok(())
    }

    /// Send ping frame
    async fn send_ping(
        &self,
        ws_sender: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            WsMessage,
        >,
        service_id: &str,
    ) -> Result<()> {
        let frame = self.new_ping_frame(service_id);
        let data = frame.encode_to_vec();

        ws_sender
            .send(WsMessage::Binary(data))
            .await
            .map_err(|e| AgentError::platform(format!("Failed to send ping: {}", e)))?;

        debug!("Ping sent");
        Ok(())
    }

    /// Create a new ping frame
    fn new_ping_frame(&self, service_id: &str) -> Frame {
        let service_id: i32 = service_id.parse().unwrap_or(0);

        Frame {
            seq_id: 0,
            log_id: 0,
            service: service_id,
            method: FrameType::Control as i32,
            headers: vec![Header {
                key: HEADER_TYPE.to_string(),
                value: MessageType::Ping.as_str().to_string(),
            }],
            payload_encoding: None,
            payload_type: None,
            payload: None,
            log_id_new: None,
        }
    }

    /// Handle incoming protobuf frame
    async fn handle_frame(
        &self,
        data: &[u8],
        event_tx: &mpsc::Sender<ChannelEvent>,
        ws_sender: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            WsMessage,
        >,
    ) -> Result<()> {
        let frame = Frame::decode(data)
            .map_err(|e| AgentError::platform(format!("Failed to decode frame: {}", e)))?;

        let frame_type = match frame.method {
            0 => FrameType::Control,
            1 => FrameType::Data,
            _ => {
                warn!("Unknown frame type: {}", frame.method);
                return Ok(());
            }
        };

        match frame_type {
            FrameType::Control => {
                self.handle_control_frame(&frame).await?;
            }
            FrameType::Data => {
                self.handle_data_frame(&frame, event_tx, ws_sender).await?;
            }
        }

        Ok(())
    }

    /// Handle control frame (ping/pong)
    async fn handle_control_frame(&self, frame: &Frame) -> Result<()> {
        let type_value = self.get_header(&frame.headers, HEADER_TYPE)?;

        match MessageType::from_str(&type_value) {
            Some(MessageType::Ping) => {
                debug!("Received ping");
            }
            Some(MessageType::Pong) => {
                debug!("Received pong");
                // Parse config update if present
                if let Some(payload) = &frame.payload {
                    if let Ok(config_str) = std::str::from_utf8(payload) {
                        if let Ok(config) = serde_json::from_str::<ClientConfig>(config_str) {
                            self.configure(&config);
                        }
                    }
                }
            }
            _ => {
                debug!("Unknown control frame type: {}", type_value);
            }
        }

        Ok(())
    }

    /// Handle data frame (events)
    async fn handle_data_frame(
        &self,
        frame: &Frame,
        event_tx: &mpsc::Sender<ChannelEvent>,
        ws_sender: &mut futures::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            WsMessage,
        >,
    ) -> Result<()> {
        let msg_id = self
            .get_header(&frame.headers, HEADER_MESSAGE_ID)
            .unwrap_or_default();
        let trace_id = self
            .get_header(&frame.headers, HEADER_TRACE_ID)
            .unwrap_or_default();
        let sum_str = self
            .get_header(&frame.headers, HEADER_SUM)
            .unwrap_or_else(|_| "1".to_string());
        let seq_str = self
            .get_header(&frame.headers, HEADER_SEQ)
            .unwrap_or_else(|_| "0".to_string());
        let type_value = self.get_header(&frame.headers, HEADER_TYPE)?;

        let sum: usize = sum_str.parse().unwrap_or(1);
        let _seq: usize = seq_str.parse().unwrap_or(0);

        // TODO: Handle message combining for large messages (sum > 1)
        if sum > 1 {
            debug!(
                "Multi-part message received (sum={}), combining not yet implemented",
                sum
            );
        }

        let payload = frame
            .payload
            .as_ref()
            .ok_or_else(|| AgentError::platform("No payload in data frame"))?;

        let message_type = MessageType::from_str(&type_value)
            .ok_or_else(|| AgentError::platform(format!("Unknown message type: {}", type_value)))?;

        debug!(
            "Received message: type={}, msg_id={}, trace_id={}",
            type_value, msg_id, trace_id
        );

        let start = std::time::Instant::now();
        let resp = match message_type {
            MessageType::Event => match self.handle_event(payload).await {
                Ok(result) => Response {
                    code: 200,
                    data: result,
                },
                Err(e) => {
                    error!("Failed to handle event: {}", e);
                    Response {
                        code: 500,
                        data: None,
                    }
                }
            },
            MessageType::Card => {
                // Card messages not yet implemented
                Response {
                    code: 200,
                    data: None,
                }
            }
            _ => Response {
                code: 200,
                data: None,
            },
        };
        let elapsed = start.elapsed().as_millis() as u64;

        // Send response back
        let resp_json = serde_json::to_string(&resp)
            .map_err(|e| AgentError::platform(format!("Failed to serialize response: {}", e)))?;

        let mut response_frame = frame.clone();
        response_frame.payload = Some(resp_json.into_bytes());

        // Add biz_rt header
        response_frame.headers.push(Header {
            key: HEADER_BIZ_RT.to_string(),
            value: elapsed.to_string(),
        });

        let resp_data = response_frame.encode_to_vec();
        ws_sender
            .send(WsMessage::Binary(resp_data))
            .await
            .map_err(|e| AgentError::platform(format!("Failed to send response: {}", e)))?;

        // Send event to channel
        if message_type == MessageType::Event {
            if let Ok(event_json) = std::str::from_utf8(payload) {
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(event_json) {
                    if let Some(channel_event) = self.convert_event(event) {
                        let _ = event_tx.send(channel_event).await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle event payload
    async fn handle_event(&self, payload: &[u8]) -> Result<Option<String>> {
        let event_str = std::str::from_utf8(payload)
            .map_err(|e| AgentError::platform(format!("Invalid UTF-8 in payload: {}", e)))?;

        debug!("Event payload: {}", event_str);

        // For now, just return None (no response data needed)
        // In the future, this could return processed results
        Ok(None)
    }

    /// Get header value by key
    fn get_header(&self, headers: &[Header], key: &str) -> Result<String> {
        headers
            .iter()
            .find(|h| h.key == key)
            .map(|h| h.value.clone())
            .ok_or_else(|| AgentError::platform(format!("Header not found: {}", key)))
    }

    /// Configure client from server config
    fn configure(&self, config: &ClientConfig) {
        if config.ping_interval.is_some() {
            self._ping_interval.store(true, Ordering::SeqCst);
        }
        debug!("Client config updated: {:?}", config);
    }

    /// Convert Lark event to ChannelEvent
    fn convert_event(&self, event: serde_json::Value) -> Option<ChannelEvent> {
        // Extract event type from the schema
        // Lark events have structure: { "schema": "2.0", "header": {...}, "event":
        // {...} }
        let schema = event.get("schema")?.as_str()?;

        if schema != "2.0" {
            warn!("Unsupported event schema: {}", schema);
            return None;
        }

        let header = event.get("header")?;
        let event_type = header.get("event_type")?.as_str()?;
        let event_id = header.get("event_id")?.as_str()?.to_string();

        let event_data = event.get("event")?;

        match event_type {
            "im.message.receive_v1" => {
                let message_data = event_data.get("message")?;
                let content = message_data.get("content")?.as_str()?;
                let chat_id = message_data.get("chat_id")?.as_str()?.to_string();
                let msg_type = message_data.get("message_type")?.as_str()?;
                let message_id = message_data.get("message_id")?.as_str()?.to_string();
                // Extract sender open_id for session management and reply routing
                let sender_open_id = event_data
                    .get("sender")
                    .and_then(|s| s.get("sender_id"))
                    .and_then(|sid| sid.get("open_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                // Parse content (it's a JSON string)
                let content_json: serde_json::Value = serde_json::from_str(content).ok()?;

                // Handle different message types
                let (message_type, content_text, metadata) = match msg_type {
                    "text" => {
                        let text = content_json.get("text")?.as_str()?.to_string();
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("message_id".to_string(), message_id.clone());
                        if let Some(ref open_id) = sender_open_id {
                            meta.insert("sender_id".to_string(), open_id.clone());
                            meta.insert("open_id".to_string(), open_id.clone());
                        }
                        meta.insert("chat_id".to_string(), chat_id.clone());
                        (CommMessageType::Text, text, meta)
                    }
                    "image" => {
                        // For image messages, content contains image_key
                        let image_key = content_json.get("image_key")?.as_str()?.to_string();
                        info!("Received image message with image_key: {}", image_key);
                        let mut meta = std::collections::HashMap::new();
                        meta.insert("message_id".to_string(), message_id.clone());
                        meta.insert("image_key".to_string(), image_key.clone());
                        if let Some(ref open_id) = sender_open_id {
                            meta.insert("sender_id".to_string(), open_id.clone());
                            meta.insert("open_id".to_string(), open_id.clone());
                        }
                        meta.insert("chat_id".to_string(), chat_id.clone());
                        // For now, treat as text with image key for processing
                        (
                            CommMessageType::Text,
                            format!("[图片] image_key: {}", image_key),
                            meta,
                        )
                    }
                    _ => {
                        info!("Received unsupported message type: {}", msg_type);
                        return None;
                    }
                };

                let message = Message {
                    id: uuid::Uuid::parse_str(&event_id).unwrap_or_else(|_| uuid::Uuid::new_v4()),
                    thread_id: uuid::Uuid::new_v4(),
                    platform: PlatformType::Lark,
                    message_type,
                    content: content_text,
                    metadata,
                    timestamp: chrono::Utc::now(),
                };

                Some(ChannelEvent::MessageReceived {
                    platform: PlatformType::Lark,
                    channel_id: chat_id,
                    message,
                })
            }
            _ => {
                debug!("Unhandled event type: {}", event_type);
                None
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    pub fn disconnect(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Start the WebSocket client (alias for connect)
    pub async fn start(&self, event_tx: mpsc::Sender<ChannelEvent>) -> Result<()> {
        self.connect(event_tx).await
    }

    /// Alias for disconnect
    pub fn stop(&self) {
        self.disconnect();
    }
}

impl Clone for LarkWebSocketClient {
    fn clone(&self) -> Self {
        Self {
            app_id: self.app_id.clone(),
            app_secret: self.app_secret.clone(),
            http_client: self.http_client.clone(),
            connected: AtomicBool::new(false),
            shutdown: Arc::new(AtomicBool::new(false)),
            access_token: Arc::new(RwLock::new(None)),
            _reconnect_count: AtomicBool::new(false),
            _reconnect_interval: AtomicBool::new(false),
            _reconnect_nonce: AtomicBool::new(false),
            _ping_interval: AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_roundtrip() {
        assert_eq!(MessageType::from_str("event"), Some(MessageType::Event));
        assert_eq!(MessageType::from_str("card"), Some(MessageType::Card));
        assert_eq!(MessageType::from_str("ping"), Some(MessageType::Ping));
        assert_eq!(MessageType::from_str("pong"), Some(MessageType::Pong));
        assert_eq!(MessageType::from_str("unknown"), None);
    }

    #[test]
    fn test_frame_encoding() {
        let frame = Frame {
            seq_id: 1,
            log_id: 2,
            service: 3,
            method: 0,
            headers: vec![Header {
                key: "type".to_string(),
                value: "ping".to_string(),
            }],
            payload_encoding: None,
            payload_type: None,
            payload: None,
            log_id_new: None,
        };

        let encoded = frame.encode_to_vec();
        let decoded = Frame::decode(&encoded[..]).unwrap();

        assert_eq!(frame.seq_id, decoded.seq_id);
        assert_eq!(frame.log_id, decoded.log_id);
        assert_eq!(frame.service, decoded.service);
        assert_eq!(frame.method, decoded.method);
        assert_eq!(frame.headers.len(), decoded.headers.len());
        assert_eq!(frame.headers[0].key, decoded.headers[0].key);
        assert_eq!(frame.headers[0].value, decoded.headers[0].value);
    }
}
