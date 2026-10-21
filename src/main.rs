use std::{env, error::Error, net::SocketAddr};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if let Some(code) = bloc::operator::dispatch(std::env::args().skip(1).collect()).await {
        std::process::exit(code);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let (config, storage) = match bloc::config::Config::environment() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("bloc: invalid server configuration");
            std::process::exit(2)
        }
    };
    let application = match bloc::administrator::Application::new(storage, config).await {
        Ok(a) => a,
        Err(_) => {
            eprintln!("bloc: credential service unavailable");
            std::process::exit(1)
        }
    };
    let address: SocketAddr = match env::var("BLOC_BIND_ADDR") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => "127.0.0.1:3000".into(),
        Err(error) => return Err(error.into()),
    }
    .parse()?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(address = %listener.local_addr()?, "bloc listening");
    axum::serve(
        listener,
        bloc::administrator::router(application)
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}
