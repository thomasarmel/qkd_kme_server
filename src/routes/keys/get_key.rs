use hyper::{Body, Request, Response};
use crate::qkd_manager::QkdManagerResponse;
use crate::routes::RequestContext;

pub(in crate::routes) fn route_get_status(rcx: &RequestContext, req: Request<Body>, slave_sae_id: &str) -> Response<Body> {
    println!("{}", req.uri().path());
    let qkd_key = match rcx.qkd_manager.get_qkd_key(slave_sae_id, rcx.get_client_certificate_serial_as_raw().unwrap()) {
        Ok(response) => match response {
            QkdManagerResponse::Key(key) => key,
            _ => {
                return Response::new(Body::from(format!("Error getting key for SAE {}", slave_sae_id)));
            }
        },
        Err(_) => {
            return Response::new(Body::from(format!("Error getting key for SAE {}", slave_sae_id)));
        }
    };
    Response::new(Body::from(format!("OK, SAE {}, cert CN: {}, cert serial: {}, your key is {}",
                                     slave_sae_id,
                                     rcx.get_client_certificate_cn().unwrap(),
                                     rcx.get_client_certificate_serial_as_string().unwrap(),
                                     qkd_key.key)))
}