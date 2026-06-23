use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Run,
    RunMigrations,
    CreateUser {
        #[arg(long)]
        username_email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = false)]
        password_stdin: bool,
    },
    DisableUser {
        #[arg(long)]
        username_email: String,
    },
    SetPassword {
        #[arg(long)]
        username_email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = false)]
        password_stdin: bool,
    },
    AddAccount {
        #[arg(long)]
        user_email: String,
        #[arg(long)]
        display_name: String,
        #[arg(long)]
        email_address: String,
        #[arg(long)]
        upstream_host: String,
        #[arg(long)]
        upstream_port: u16,
        #[arg(long)]
        upstream_tls_mode: String,
        #[arg(long)]
        upstream_auth_method: String,
        #[arg(long)]
        upstream_username: String,
        #[arg(long)]
        upstream_secret: Option<String>,
        #[arg(long, default_value_t = false)]
        upstream_secret_stdin: bool,
    },
    DisableAccount {
        #[arg(long)]
        account_email: String,
    },
    PauseSync {
        #[arg(long)]
        account_email: String,
    },
    ResumeSync {
        #[arg(long)]
        account_email: String,
    },
    DeleteAccount {
        #[arg(long)]
        account_email: String,
    },
    TestUpstream {
        #[arg(long)]
        account_email: String,
    },
    ForceSync {
        #[arg(long)]
        account_email: String,
    },
    ResetMailboxState {
        #[arg(long)]
        account_email: String,
        #[arg(long)]
        mailbox: String,
    },
    ClearCache {
        #[arg(long)]
        account_email: String,
    },
    ListAccounts {
        #[arg(long)]
        user_email: String,
    },
    ListMailboxes {
        #[arg(long)]
        account_email: String,
    },
    ShowSyncStatus {
        #[arg(long)]
        account_email: String,
        #[arg(long)]
        mailbox: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::Run) => {
            let config = imap_cache_rs::config::Config::load(cli.config.as_deref())?;
            imap_cache_rs::security::ensure_rustls_crypto_provider();
            imap_cache_rs::protocol::init_tracing(&config.log_level)?;
            imap_cache_rs::run(config).await
        }
        Some(Command::RunMigrations) => {
            let config = imap_cache_rs::config::Config::load(cli.config.as_deref())?;
            imap_cache_rs::security::ensure_rustls_crypto_provider();
            imap_cache_rs::protocol::init_tracing(&config.log_level)?;
            imap_cache_rs::admin::run_migrations_only(&config).await?;
            Ok(())
        }
        Some(Command::CreateUser {
            username_email,
            password,
            password_stdin,
        }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::CreateUser {
                    username_email,
                    password,
                    password_stdin,
                },
            )
            .await
        }
        Some(Command::DisableUser { username_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::DisableUser { username_email },
            )
            .await
        }
        Some(Command::SetPassword {
            username_email,
            password,
            password_stdin,
        }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::SetPassword {
                    username_email,
                    password,
                    password_stdin,
                },
            )
            .await
        }
        Some(Command::AddAccount {
            user_email,
            display_name,
            email_address,
            upstream_host,
            upstream_port,
            upstream_tls_mode,
            upstream_auth_method,
            upstream_username,
            upstream_secret,
            upstream_secret_stdin,
        }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::AddAccount {
                    user_email,
                    display_name,
                    email_address,
                    upstream_host,
                    upstream_port,
                    upstream_tls_mode,
                    upstream_auth_method,
                    upstream_username,
                    upstream_secret,
                    upstream_secret_stdin,
                },
            )
            .await
        }
        Some(Command::DisableAccount { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::DisableAccount { account_email },
            )
            .await
        }
        Some(Command::PauseSync { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::PauseSync { account_email },
            )
            .await
        }
        Some(Command::ResumeSync { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ResumeSync { account_email },
            )
            .await
        }
        Some(Command::DeleteAccount { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::DeleteAccount { account_email },
            )
            .await
        }
        Some(Command::TestUpstream { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::TestUpstream { account_email },
            )
            .await
        }
        Some(Command::ForceSync { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ForceSync { account_email },
            )
            .await
        }
        Some(Command::ResetMailboxState {
            account_email,
            mailbox,
        }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ResetMailboxState {
                    account_email,
                    mailbox,
                },
            )
            .await
        }
        Some(Command::ClearCache { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ClearCache { account_email },
            )
            .await
        }
        Some(Command::ListAccounts { user_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ListAccounts { user_email },
            )
            .await
        }
        Some(Command::ListMailboxes { account_email }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ListMailboxes { account_email },
            )
            .await
        }
        Some(Command::ShowSyncStatus {
            account_email,
            mailbox,
        }) => {
            run_admin(
                cli.config,
                imap_cache_rs::admin::AdminCommand::ShowSyncStatus {
                    account_email,
                    mailbox,
                },
            )
            .await
        }
    }
}

async fn run_admin(
    config_path: Option<std::path::PathBuf>,
    command: imap_cache_rs::admin::AdminCommand,
) -> anyhow::Result<()> {
    let config = imap_cache_rs::config::Config::load(config_path.as_deref())?;
    imap_cache_rs::security::ensure_rustls_crypto_provider();
    imap_cache_rs::protocol::init_tracing(&config.log_level)?;
    let output = imap_cache_rs::admin::run_admin_command(&config, command).await?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}
