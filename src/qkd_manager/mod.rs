mod key_handler;

use std::thread;
use crate::qkd_manager::QkdManagerResponse::TransmissionError;

#[derive(Clone)]
pub struct QkdManager {
    command_tx: crossbeam_channel::Sender<QkdManagerCommand>,
    response_rx: crossbeam_channel::Receiver<QkdManagerResponse>,
}

impl QkdManager {
    pub fn new() -> Self {
        let (command_tx, command_rx) = crossbeam_channel::unbounded::<QkdManagerCommand>();
        let (response_tx, response_rx) = crossbeam_channel::unbounded::<QkdManagerResponse>();
        thread::spawn(move || {
            let mut key_handler = key_handler::KeyHandler::new(command_rx, response_tx);
            key_handler.run();
        });
        Self {
            command_tx,
            response_rx,
        }
    }

    pub fn add_qkd_key(&self, sae_id: &str, key: QkdKey) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::AddKey(String::from(sae_id), key)).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Ok => Ok(QkdManagerResponse::Ok),
            qkd_response_error => Err(qkd_response_error),
        }
    }

    pub fn get_qkd_key(&self, sae_id: &str, auth_client_cert_serial: &[u8]) -> Result<QkdManagerResponse, QkdManagerResponse> {
        self.command_tx.send(QkdManagerCommand::GetKey(String::from(sae_id))).map_err(|_| {
            TransmissionError
        })?;
        match self.response_rx.recv().map_err(|_| {
            TransmissionError
        })? {
            QkdManagerResponse::Key(key) => {
                if key.auth_client_cert_serial != auth_client_cert_serial {
                    return Err(QkdManagerResponse::AuthenticationError);
                }
                Ok(QkdManagerResponse::Key(key))
            },
            qkd_response_error => Err(qkd_response_error),
        }
    }
}

#[derive(Debug, Clone)]
pub struct QkdKey {
    pub(crate) key: String,
    auth_client_cert_serial: Vec<u8>,
}

impl QkdKey {
    pub fn new(key: &str, auth_client_cert_serial: &[u8]) -> Self {
        Self {
            key: String::from(key),
            auth_client_cert_serial: Vec::from(auth_client_cert_serial),
        }
    }
}

enum QkdManagerCommand {
    AddKey(String, QkdKey),
    GetKey(String),
}

#[derive(Debug)]
pub enum QkdManagerResponse {
    Ok,
    Ko,
    TransmissionError,
    AuthenticationError,
    Key(QkdKey),
}