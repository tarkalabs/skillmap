use crate::db::DB;
use async_session::MemoryStore;
use color_eyre::{Help, Result};
use oauth2::{basic::BasicClient, AuthUrl, ClientSecret, RedirectUrl, TokenUrl};
use std::sync::Arc;
use tracing::instrument;

#[derive(Clone, Debug)]
pub struct AppState {
    db: Arc<DB>,
    client: BasicClient,
    session_store: MemoryStore,
}

impl AppState {
    #[instrument]
    pub async fn init() -> Result<Self> {
        let db = DB::new()
            .await
            .suggestion("Ensure that the Database URL environment variable is correct")?;
        let client = BasicClient::new(
            oauth2::ClientId::new("1027249500571566170".to_owned()),
            Some(ClientSecret::new(
                "ihmjdHIJjgWib-Z3aHzFGFMd1jpFUM8c".to_owned(),
            )),
            AuthUrl::new("https://discord.com/oauth2/authorize".to_owned()).unwrap(),
            Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_owned()).unwrap()),
        )
        .set_redirect_uri(
            RedirectUrl::new("http://127.0.0.1:3000/auth/authorized".to_owned()).unwrap(),
        );

        let session_store = MemoryStore::new();

        Ok(AppState {
            db: Arc::new(db),
            client,
            session_store,
        })
    }
    pub fn db(&self) -> Arc<DB> {
        self.db.clone()
    }
    pub fn client(&self) -> BasicClient {
        self.client.clone()
    }
    pub fn session_store(&self) -> MemoryStore {
        self.session_store.clone()
    }
    pub fn init_with_db(db: DB) -> Self {
        let client = BasicClient::new(
            oauth2::ClientId::new("1027249500571566170".to_owned()),
            Some(ClientSecret::new(
                "ihmjdHIJjgWib-Z3aHzFGFMd1jpFUM8c".to_owned(),
            )),
            AuthUrl::new("https://discord.com/oauth2/authorize".to_owned()).unwrap(),
            Some(TokenUrl::new("https://discord.com/api/oauth2/token".to_owned()).unwrap()),
        )
        .set_redirect_uri(
            RedirectUrl::new("http://127.0.0.1:3000/auth/authorized".to_owned()).unwrap(),
        );

        let session_store = MemoryStore::new();

        AppState {
            db: Arc::new(db),
            client,
            session_store,
        }
    }
}
