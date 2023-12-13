use hyper::{Body, Request, Response};

pub(in crate::routes) fn route_get_status(req: Request<Body>, slave_SAE_ID: &str) -> Response<Body> {
    println!("{}", req.uri().path());
    Response::new(Body::from("OK"))
}