use std::collections::HashMap;
use crate::qkd_manager;
use crate::qkd_manager::{QkdManagerCommand, QkdManagerResponse};

pub(super) struct KeyHandler {
    command_rx: crossbeam_channel::Receiver<QkdManagerCommand>,
    response_tx: crossbeam_channel::Sender<QkdManagerResponse>,
    /// Map of SAE ID to key
    keys: HashMap<String, qkd_manager::QkdKey>,
}

impl KeyHandler {
    pub(super) fn new(command_rx: crossbeam_channel::Receiver<QkdManagerCommand>, response_tx: crossbeam_channel::Sender<QkdManagerResponse>) -> Self {
        Self {
            command_rx,
            response_tx,
            keys: HashMap::new(),
        }
    }

    pub(super) fn run(&mut self) {
        loop {
            match self.command_rx.recv() {
                Ok(cmd) => {
                    match cmd {
                        QkdManagerCommand::AddKey(sae_id, key) => {
                            println!("Adding key for SAE ID {}", sae_id);
                            self.keys.insert(sae_id, key);
                            self.response_tx.send(QkdManagerResponse::Ok).unwrap();
                        },
                        QkdManagerCommand::GetKey(sae_id) => {
                            println!("Getting key for SAE ID {}", sae_id);
                            match self.keys.get(&sae_id) {
                                Some(key) => {
                                    self.response_tx.send(QkdManagerResponse::Key(key.clone())).unwrap();
                                },
                                None => {
                                    println!("Key not found for SAE ID {}", sae_id);
                                    self.response_tx.send(QkdManagerResponse::Ko).unwrap();
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("Error receiving command: {:?}", e);
                }
            }
        }
    }
}