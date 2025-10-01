//! Interface for important event subscribers, supposed to be used for demonstration purpose

use std::future::Future;
use std::io;
use std::pin::Pin;

/// Trait that should be implemented by important event subscribers
/// Only events useful for demonstration purpose will be sent to the subscribers
pub trait ImportantEventSubscriber where Self: Sync + Send {
    /// Receive a notification for an important event
    /// # Arguments
    /// * `message` - The notification message that should be sent to the subscriber
    /// # Returns
    /// An io::Error if the notification could not be sent, likely because of sync issue, or Ok(()) if the notification was sent successfully
    fn notify(&self, message: &str) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + '_>>;
}