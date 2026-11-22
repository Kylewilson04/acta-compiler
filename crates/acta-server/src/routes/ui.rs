use axum::response::Html;

const CONTROL_PLANE_HTML: &str = include_str!("../ui.html");

/// `GET /` -> Serves the embedded Acta V1.0 Production Control Plane UI.
pub async fn handle_index_ui() -> Html<&'static str> {
    Html(CONTROL_PLANE_HTML)
}
