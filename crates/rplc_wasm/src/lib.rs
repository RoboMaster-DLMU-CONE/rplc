use rplc_core::{generate, validate};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[derive(serde::Serialize)]
pub struct JsDiagnostic {
    pub severity: String,
    pub message: String,
    pub span: Option<(usize, usize)>,
}

// {
// "severity": "Error",
// "message": "Packet名称 'bad_name' 不合法",
// "span": [15, 8]
// }

#[wasm_bindgen]
pub fn check_json(input: &str) -> JsValue {
    let raw_diags = validate(input);

    let js_diags: Vec<JsDiagnostic> = raw_diags
        .into_iter()
        .map(|d| JsDiagnostic {
            severity: format!("{:?}", d.severity),
            message: d.code.to_string(),
            span: d.span,
        })
        .collect();

    serde_wasm_bindgen::to_value(&js_diags).unwrap()
}

#[wasm_bindgen]
pub fn compile_cpp(input: &str) -> Result<String, String> {
    generate(input).map_err(|e| e.to_string())
}
