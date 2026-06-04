//! A simple example to send a test email

use std::env::VarError;

use clap::Parser;
use mailgun::mail::{Message, Text};

#[derive(Debug, clap::Parser)]
struct Args {
    /// Destination email address
    from: String,

    /// Source email address
    to: String,

    /// Email domain
    #[clap(long)]
    domain: Option<String>,
}

#[tokio::main]
async fn main() {
    let mut args = Args::parse();

    let token = get_env("MAILGUN_API_KEY");
    let domain = args.domain.unwrap_or_else(|| get_env("MAILGUN_DOMAIN"));

    if domain.starts_with("sandbox") {
        args.from = get_env("MAILGUN_SANDBOX_FROM");
    }

    let client = mailgun::MailgunClient::new(token);

    let message = Message {
        from: args.from.parse().unwrap(),
        to: vec![args.to.parse().unwrap()],
        subject: "A demonstration of emporium".into(),
        body: Text("This is a demonstration of emporium sending mailgun mail".into()).into(),
        ..Default::default()
    };

    eprintln!(
        "Sending from {} to {:?}",
        message.from,
        message
            .to
            .iter()
            .map(|email| email.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let response = client
        .send_email(&domain, &message)
        .await
        .expect("unable to send email");
    eprintln!("MailGun: {}", response.message);
}

fn get_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(VarError::NotPresent) => {
            panic!("{name} not set")
        }
        Err(VarError::NotUnicode(_)) => {
            panic!("{name} is not valid UTF-8");
        }
    }
}
