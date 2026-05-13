use serde::Deserialize;
use serde_json::Value;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct OpenRpcDoc {
    pub openrpc: String,
    pub info: Info,
    pub methods: Vec<Method>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Info {
    pub title: String,
    pub version: String,
    pub description: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Method {
    pub name: String,
    pub description: String,
    pub params: Vec<Param>,
    pub result: ResultDoc,
    #[serde(rename = "x-bitcoin-category")]
    pub category: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Param {
    pub name: String,
    pub required: bool,
    pub schema: Value,
    #[serde(default)]
    pub description: Option<String>,
    /// Argument is kept only for wire compatibility; callers should omit it.
    #[serde(rename = "x-bitcoin-placeholder", default)]
    pub placeholder: bool,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ResultDoc {
    pub name: String,
    pub schema: Value,
}
