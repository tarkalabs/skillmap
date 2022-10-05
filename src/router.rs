use crate::{app_state::AppState, model::User};
use async_session::{async_trait, MemoryStore, Session, SessionStore};
use axum::{
    body::Body,
    extract::{rejection::TypedHeaderRejectionReason, FromRequest, Query, RequestParts},
    http::{Request, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Json, Router, TypedHeader,
};
use color_eyre::Result;
use http::{header::COOKIE, header::SET_COOKIE, HeaderMap};
use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::instrument;

async fn home_handler() -> String {
    String::from("Hello server\n")
}

#[derive(Debug, Serialize, Deserialize)]
struct DiscordUser {
    id: String,
    avatar: Option<String>,
    username: String,
    discriminator: String,
}

static COOKIE_NAME: &str = "SESSION";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
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
    let (auth_url, _csrf_token) = &state
        .client()
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .url();

    // Redirect to Discord's oauth service
    Redirect::to(auth_url.as_ref())
}

async fn login_authorized(
    Query(query): Query<AuthRequest>,
    Extension(state): Extension<AppState>,
) -> impl IntoResponse {
    // Get an auth token
    let token = state
        .client()
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .unwrap();

    // Fetch user data from discord
    let client = reqwest::Client::new();
    let user_data: DiscordUser = client
        // https://discord.com/developers/docs/resources/user#get-current-user
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .unwrap()
        .json::<DiscordUser>()
        .await
        .unwrap();

    // Create a new session filled with user data
    let mut session = Session::new();
    session.insert("user", &user_data).unwrap();

    // Store session and get corresponding cookie
    let cookie = state
        .session_store()
        .store_session(session)
        .await
        .unwrap()
        .unwrap();

    // Build the cookie
    let cookie = format!("{}={}; SameSite=Lax; Path=/", COOKIE_NAME, cookie);

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    (headers, Redirect::to("/"))
}

async fn protected(user: DiscordUser) -> impl IntoResponse {
    format!(
        "Welcome to the protected area :)\nHere's your info:\n{:?}",
        user
    )
}

#[instrument]
pub async fn build_router(app_state: AppState) -> Result<Router<Body>> {
    // let shared_state = app_state::AppState::init().await.context("error initializing state")?;
    let router = Router::new()
        .route("/", get(home_handler))
        .route("/users", get(users_handler))
        .route("/users", post(create_user_handler))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/protected", get(protected))
        .layer(
            ServiceBuilder::new()
                .layer(Extension(app_state))
                .layer(TraceLayer::new_for_http()),
        );
    Ok(router)
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/discord").into_response()
    }
}

#[async_trait]
impl<S> FromRequest<S> for DiscordUser
where
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request(parts: &mut RequestParts<S>) -> Result<Self, Self::Rejection> {
        let state = parts.extensions().get::<AppState>();
        let store = state.unwrap().session_store();

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {}", e),
                },
                _ => panic!("unexpected error getting cookies: {}", e),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<DiscordUser>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}
