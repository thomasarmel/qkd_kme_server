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

    pub(super) fn add_kme_to_ip_domain_port_association(&mut self, kme_id: KmeId, ip_or_domain: &str, client_cert_path: &str, client_cert_password: &str, should_ignore_system_proxy_settings: bool) -> Result<(), io::Error> {
        if !Self::check_ip_port_domain_url_validity(ip_or_domain) {
            return Err(io_err("Invalid IP, domain and port"));
        }
        let mut buf = Vec::new();
        File::open(client_cert_path)
            .map_err(|e| io_err(&format!("Cannot open client certificate file: {:?}", e)))?
            .read_to_end(&mut buf)
            .map_err(|e| io_err(&format!("Cannot read client certificate file: {:?}", e)))?;
        let tls_client_cert_identity = reqwest::tls::Identity::from_pkcs12_der(&buf, client_cert_password)
            .map_err(|e| io_err(&format!("Cannot create client certificate identity: {:?}", e)))?;
        self.kme_to_classical_network_info_associations.insert(kme_id, KmeInfoClassicalNetwork {
            ip_domain_port: ip_or_domain.to_string(),
            tls_client_cert_identity,
            should_ignore_system_proxy_settings,
        });
        Ok(())
    }

    pub(super) fn get_classical_connection_info_from_kme_id(&self, kme_id: KmeId) -> Option<&KmeInfoClassicalNetwork> {
        self.kme_to_classical_network_info_associations.get(&kme_id)
    }

    fn check_ip_port_domain_url_validity(ip_domain_port: &str) -> bool {
        let url = url::Url::parse(&format!("https://{}", ip_domain_port));
        url.is_ok()
    }
}

#[derive(Clone)]
pub(super) struct KmeInfoClassicalNetwork {
    pub(super) ip_domain_port: String,
    pub(super) tls_client_cert_identity: reqwest::tls::Identity,
    pub(super) should_ignore_system_proxy_settings: bool,
}

#[cfg(test)]
mod tests {
    use crate::qkd_manager::router::QkdRouter;

    #[test]
    fn test_add_kme_to_ip_or_domain_association() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "certs/inter_kmes/client-kme1-to-kme2.pfx";
        let client_cert_password = "";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        assert!(qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, client_cert_password, true).is_ok());
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_some());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_wrong_domain() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234;invalid_data";
        let client_cert_path = "certs/inter_kmes/client-kme1-to-kme2.pfx";
        let client_cert_password = "";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, client_cert_password, true);
        assert!(qkd_router_add_result.is_err());
        assert_eq!(qkd_router_add_result.err().unwrap().to_string(), "Invalid IP, domain and port");
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_cert_file_does_not_exist() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "not-exists.pfx";
        let client_cert_password = "";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, client_cert_password, true);
        assert!(qkd_router_add_result.is_err());
        assert_eq!(qkd_router_add_result.err().unwrap().to_string(), "Cannot open client certificate file: Os { code: 2, kind: NotFound, message: \"No such file or directory\" }");
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_cert_file_invalid() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "tests/data/bad_certs/invalid_client_cert_data.pfx";
        let client_cert_password = "";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, client_cert_password, true);
        assert!(qkd_router_add_result.is_err());
        assert!(qkd_router_add_result.err().unwrap().to_string().starts_with("Cannot create client certificate identity: "));
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }

    #[test]
    fn test_add_kme_to_ip_or_domain_association_wrong_cert_password() {
        let mut qkd_router = QkdRouter::new();
        let kme_id = 1;
        let ip_domain_port = "test.fr:1234";
        let client_cert_path = "certs/inter_kmes/client-kme1-to-kme2.pfx";
        let client_cert_password = "this is not the password";

        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
        let qkd_router_add_result = qkd_router.add_kme_to_ip_domain_port_association(kme_id, ip_domain_port, client_cert_path, client_cert_password, true);
        assert!(qkd_router_add_result.is_err());
        assert!(qkd_router_add_result.err().unwrap().to_string().starts_with("Cannot create client certificate identity: "));
        assert!(qkd_router.get_classical_connection_info_from_kme_id(kme_id).is_none());
    }
}