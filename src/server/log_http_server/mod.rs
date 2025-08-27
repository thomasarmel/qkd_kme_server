//! HTTP server for logging important events, in a demonstration purpose (intended to be visited using a web browser)
//! Events are displayed on index HTML page, and retrieved periodically by AJAX requests from /messages

mod logging_message;

use std::convert::Infallible;
use std::io;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use crate::event_subscription::ImportantEventSubscriber;
use crate::server::log_http_server::logging_message::LoggingMessage;

/// HTTP logging server struct
#[derive(Debug)]
pub struct LoggingHttpServer {
    /// HTTP listen address, e.g. "0.0.0.0:8080"
    pub listen_addr: String,
    received_log_messages: Arc<Mutex<Vec<LoggingMessage>>>,
}

impl LoggingHttpServer {
    /// Create a new HTTP logging server
    /// # Arguments
    /// * `listen_addr` - The address to listen for HTTP connections, e.g. "0.0.0.0:8080"
    /// # Returns
    /// A new LoggingHttpServer
    pub fn new(listen_addr: &str) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            received_log_messages: Arc::new(Mutex::new(Vec::new())),
        }
    }
    /// Run the HTTP server
    /// # Arguments
    /// * `qkd_manager` - The QKD manager associated with this logging server
    /// # Returns
    /// Never (`!`) in case of success, an io::Error otherwise
    pub async fn run(&self) -> Result<(), io::Error> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        loop {
            let (stream, _) = listener.accept().await?;

            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            // `hyper::rt` IO traits.
            let io = TokioIo::new(stream);
            let received_log_messages = Arc::clone(&self.received_log_messages);

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `hello` service
                if let Err(err) = http1::Builder::new()
                    // We could think about passing &self as argument when ! type would be released
                    .serve_connection(io, service_fn(|incoming_request| Self::handle_incoming_request(incoming_request, Arc::clone(&received_log_messages))))
                    .await
                {
                    eprintln!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    /// Called at each incoming request
    async fn handle_incoming_request(request: Request<hyper::body::Incoming>, received_log_messages: Arc<Mutex<Vec<LoggingMessage>>>) -> Result<Response<Full<Bytes>>, Infallible> {
        const INDEX_HTML_RESPONSE: &str = include_str!("index.html");

        let response_obj = match request.uri().path() {
            "/messages" => {
                Self::generate_messages_http_json_response(&received_log_messages)
            },
            _ => {
                Response::new(Full::new(Bytes::from(INDEX_HTML_RESPONSE.to_string())))
            }
        };
        Ok(response_obj)
    }

    /// Generates JSON array HTTP response containing all received log messages, or HTTP error status if an error occurred
    fn generate_messages_http_json_response(received_log_messages: &Arc<Mutex<Vec<LoggingMessage>>>) -> Response<Full<Bytes>> {
        let received_log_messages = match received_log_messages.lock() {
            Ok(received_log_messages) => received_log_messages,
            Err(_) => {
                return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Full::new(Bytes::from(String::from("Mutex lock error")))).unwrap();
            }
        };
        let response_str = match serde_json::to_string(&received_log_messages.deref()) {
            Ok(response_str) => response_str,
            Err(_) => {
                return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(Full::new(Bytes::from(String::from("JSON serialization error")))).unwrap();
            }
        };
        Response::builder().status(StatusCode::OK).header(CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(response_str))).unwrap()
    }
}

impl ImportantEventSubscriber for LoggingHttpServer {
    /// Add a notification message to be displayed on the HTTP page
    /// # Arguments
    /// * `message` - The message to be displayed
    /// # Returns
    /// Result<(), io::Error> - Ok(()) if the message was successfully added, Err(io::Error) otherwise (mutex lock error)
    fn notify(&self, message: &str) -> Result<(), io::Error> {
        self.received_log_messages
            .lock()
            .map_err(|_|
                io::Error::new(io::ErrorKind::Other, "Mutex lock error"
                ))?
            .push(LoggingMessage::new(message));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use regex::Regex;
    use serial_test::serial;
    use crate::event_subscription::ImportantEventSubscriber;
    use crate::server::log_http_server::LoggingHttpServer;

    #[tokio::test]
    #[serial]
    async fn test_logging_http_server() {
        const EXPECTED_INDEX_BODY: &'static str = include_str!("index.html");

        let server = Arc::new(LoggingHttpServer::new("127.0.0.1:8080"));
        let server_copy_coroutine = Arc::clone(&server);
        tokio::spawn(async move {
            server_copy_coroutine.run().await.unwrap();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await; // To ensure server task is scheduled before client
        let get_index_response = reqwest::get("http://127.0.0.1:8080").await.unwrap();
        assert_eq!(get_index_response.status(), 200);
        assert_eq!(get_index_response.text().await.unwrap(), EXPECTED_INDEX_BODY);

        let get_messages_response = reqwest::get("http://127.0.0.1:8080/messages").await.unwrap();
        assert_eq!(get_messages_response.status(), 200);
        assert_eq!(get_messages_response.text().await.unwrap(), "[]");

        server.notify("Hello").unwrap();
        server.notify("World").unwrap();

        let get_messages_response = reqwest::get("http://127.0.0.1:8080/messages").await.unwrap();
        assert_eq!(get_messages_response.status(), 200);
        let check_json_regex = Regex::new(r#"\[\{"message":"Hello","datetime":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"},\{"message":"World","datetime":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"}]"#).unwrap();
        assert!(check_json_regex.is_match(&get_messages_response.text().await.unwrap()));
    }
}