use serde::Serialize;

pub(crate) trait HttpResponseBody where Self: serde::Serialize {
    fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
    }
}

#[derive(Serialize)]
pub(crate) struct ResponseError {
    pub(crate) message: String,
}
impl HttpResponseBody for ResponseError {} // can't use Derive macro because of the generic constraint