use hyper::{Body, Request, Response};
use crate::routes::RequestContext;

pub(in crate::routes) fn route_get_status(rcx: &RequestContext, req: Request<Body>, slave_sae_id: &str) -> Response<Body> {
    println!("{}", req.uri().path());
    Response::new(Body::from(format!("OK, SAE {}, cert CN: {}, cert serial: {}",
                                     slave_sae_id,
                                     rcx.get_client_certificate_cn().unwrap(),
                                     rcx.get_client_certificate_serial_as_string().unwrap())))
}