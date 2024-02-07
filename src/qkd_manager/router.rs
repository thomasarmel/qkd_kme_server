//! QKD network routing manager, get route to SAE and KME info on classical network

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Read;
use crate::{io_err, KmeId};

#[derive(Clone)]
pub(super) struct QkdRouter {
    kme_to_classical_network_info_associations: HashMap<KmeId, KmeInfoClassicalNetwork>,
}

impl QkdRouter {
    pub(super) fn new() -> Self {
        Self {
            kme_to_classical_network_info_associations: HashMap::new(),
        }
    }

    pub(super) fn add_kme_to_ip_or_domain_association(&mut self, kme_id: KmeId, ip_or_domain: &str, client_cert_path: &str, client_cert_password: &str) -> Result<(), io::Error> {
        let mut buf = Vec::new();
        File::open(client_cert_path)
            .map_err(|e| io_err(&format!("Cannot open client certificate file: {:?}", e)))?
            .read_to_end(&mut buf)
            .map_err(|e| io_err(&format!("Cannot read client certificate file: {:?}", e)))?;
        let tls_client_cert_identity = reqwest::tls::Identity::from_pkcs12_der(&buf, client_cert_password)
            .map_err(|e| io_err(&format!("Cannot create client certificate identity: {:?}", e)))?;
        self.kme_to_classical_network_info_associations.insert(kme_id, KmeInfoClassicalNetwork {
            ip_or_domain: ip_or_domain.to_string(),
            tls_client_cert_identity,
        });
        Ok(())
    }

    pub(super) fn get_classical_connection_info_from_kme_id(&self, kme_id: KmeId) -> Option<&KmeInfoClassicalNetwork> {
        self.kme_to_classical_network_info_associations.get(&kme_id)
    }
}

#[derive(Clone)]
pub(super) struct KmeInfoClassicalNetwork {
    pub(super) ip_or_domain: String,
    pub(super) tls_client_cert_identity: reqwest::tls::Identity,
}