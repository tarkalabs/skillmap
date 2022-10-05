use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Response, Redirect},
    routing::{get, post},
    Extension, Json, Router,
};
use color_eyre::Result;
use oauth2::{CsrfToken, Scope};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::instrument;

use crate::{app_state::AppState, model::User};

async fn home_handler() -> String {
    String::from("Hello server\n")
}

#[instrument]
async fn users_handler(req: Request<Body>) -> Result<Json<Vec<User>>, StatusCode> {
    let state = req
        .extensions()
        .get::<AppState>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let users = User::all(&state.db().connection()).await.map_err(|err| {
        tracing::error!("{:?}", err);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(users))
}

#[instrument]
async fn create_user_handler(
    Json(mut payload): Json<User>,
    Extension(state): Extension<AppState>,
) -> Result<Response, StatusCode> {
    payload
        .insert(&state.db().connection())
        .await
        .map_err(|err| {
            tracing::error!("{:?}", err);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok((StatusCode::CREATED, [("Content-Type", "application/json")]).into_response())
}

#[instrument]
async fn discord_auth(Extension(state): Extension<AppState>) -> impl IntoResponse {
    let (auth_url, _csrf_token) = &state.client()
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .url();

    // Redirect to Discord's oauth service
    Redirect::to(auth_url.as_ref())
}

#[instrument]
pub async fn build_router(app_state: AppState) -> Result<Router<Body>> {
    // let shared_state = app_state::AppState::init().await.context("error initializing state")?;
    let router = Router::new()
        .route("/", get(home_handler))
        .route("/users", get(users_handler))
        .route("/users", post(create_user_handler))
        .route("/auth/discord", get(discord_auth))
        .layer(
            ServiceBuilder::new()
                .layer(Extension(app_state))
                .layer(TraceLayer::new_for_http()),
        );
    Ok(router)
}
