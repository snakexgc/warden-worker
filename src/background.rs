use std::future::Future;
use wasm_bindgen_futures::spawn_local;
use worker::Context;

pub struct BackgroundExecutor {
    context: Option<Context>,
}

impl BackgroundExecutor {
    pub fn from_context(context: Context) -> Self {
        Self {
            context: Some(context),
        }
    }

    pub fn detached() -> Self {
        Self { context: None }
    }

    pub fn wait_until<F>(&self, fut: F)
    where
        F: Future<Output = ()> + 'static,
    {
        if let Some(context) = &self.context {
            context.wait_until(fut);
        } else {
            spawn_local(fut);
        }
    }
}