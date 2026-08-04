use std::sync::OnceLock;
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::{DurableObject, Env, HttpRequest, Request, Response, Result, State, durable_object};

pub struct HeavyDoState {
    router: axum::Router,
}

#[durable_object]
pub struct HeavyDo {
    _state: State,
    env: Env,
    initialized: OnceLock<HeavyDoState>,
}

impl DurableObject for HeavyDo {
    fn new(state: State, env: Env) -> Self {
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(log::Level::Debug);

        Self {
            _state: state,
            env,
            initialized: OnceLock::new(),
        }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        if crate::api::notifications::is_notifications_path(&req.path()) {
            return crate::api::notifications::proxy_notifications_request(&self.env, req).await;
        }

        let state = self.get_or_init_state().await?;

        let (city, region, country) = {
            if let Some(cf) = req.cf() {
                (cf.city(), cf.region(), cf.country())
            } else {
                (None, None, None)
            }
        };

        let mut http_req = HttpRequest::try_from(req)?;
        let mut inject = |k: &'static str, v: Option<String>| {
            if let Some(v) = v
                && let Ok(hv) = axum::http::HeaderValue::from_str(&v)
            {
                http_req.headers_mut().insert(k, hv);
            }
        };
        inject("X-CF-City", city);
        inject("X-CF-Region", region);
        inject("X-CF-Country", country);

        let mut app = state.router.clone();
        let http_resp = app
            .call(http_req)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;
        Response::try_from(http_resp)
    }
}

impl HeavyDo {
    async fn get_or_init_state(&self) -> Result<&HeavyDoState> {
        if let Some(state) = self.initialized.get() {
            return Ok(state);
        }

        let db = self
            .env
            .d1("vaultsql")
            .map_err(|e| worker::Error::RustError(format!("Failed to get database: {}", e)))?;

        let jwt_keys = crate::worker_runtime::jwt_manager::JwtKeyManager::get_or_create_keys(&db)
            .await
            .map_err(|e| {
                worker::Error::RustError(format!("Failed to initialize JWT keys: {}", e))
            })?;

        let two_factor_key =
            crate::worker_runtime::two_factor_key_manager::TwoFactorKeyManager::get_or_create_key(
                &db,
            )
            .await
            .map_err(|e| {
                worker::Error::RustError(format!("Failed to initialize two-factor key: {}", e))
            })?;

        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any);

        let router = crate::api::router::api_router_with_keys(
            self.env.clone(),
            None,
            jwt_keys,
            two_factor_key,
        )
        .layer(cors);

        let state = HeavyDoState { router };

        let _ = self.initialized.set(state);

        Ok(self.initialized.get().unwrap())
    }
}
