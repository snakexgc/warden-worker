use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::{durable_object, DurableObject, Env, HttpRequest, Request, Response, Result, State};

#[durable_object]
pub struct HeavyDo {
    #[allow(dead_code)]
    state: State,
    env: Env,
    router: axum::Router,
}

impl DurableObject for HeavyDo {
    fn new(state: State, env: Env) -> Self {
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(log::Level::Debug);

        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any);
        let router = crate::router::api_router(env.clone(), None).layer(cors);

        Self { state, env, router }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if crate::notifications::is_notifications_path(&req.path()) {
            return crate::notifications::proxy_notifications_request(&self.env, req).await;
        }

        let (city, region, country) = {
            if let Some(cf) = req.cf() {
                (cf.city(), cf.region(), cf.country())
            } else {
                (None, None, None)
            }
        };

        let mut http_req = HttpRequest::try_from(req)?;
        let mut inject = |k: &'static str, v: Option<String>| {
            if let Some(v) = v {
                if let Ok(hv) = axum::http::HeaderValue::from_str(&v) {
                    http_req.headers_mut().insert(k, hv);
                }
            }
        };
        inject("X-CF-City", city);
        inject("X-CF-Region", region);
        inject("X-CF-Country", country);

        let mut app = self.router.clone();
        let http_resp = app
            .call(http_req)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        Response::try_from(http_resp)
    }
}
