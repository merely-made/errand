//! The `misfin` command-line tool (the `cli` feature): mint identities, send
//! mail, run a mailserver, and read an inbox.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use misfin::{
    MailboxStore, MisfinAddress, MisfinIdentitySpec, MisfinServer, MisfinServerConfig, SendOptions,
    ServedMailbox, ensure_identity_with_root, identity_material_with_root, send,
};

const USAGE: &str = "misfin — the Misfin mail protocol (spec: github.com/JCLemme/misfin)

USAGE:
  misfin id <mailbox@host> [--blurb TEXT] [--root DIR]
      Mint (or show) a persisted identity; prints its fingerprint.

  misfin send <recipient@host> <message...> --from <mailbox@host>
              [--blurb TEXT] [--root DIR] [--port N] [--pin FINGERPRINT]
      Deliver one message. The --from identity is minted on first use.

  misfin serve <mailbox@host> [<mailbox@host>...] [--store FILE]
               [--listen ADDR:PORT] [--root DIR]
      Run a mailserver for the given mailboxes (they must share a host).
      The first mailbox's certificate is the server's TLS identity.

  misfin inbox <mailbox@host> [--store FILE]
      List messages delivered to a mailbox of a local `misfin serve` store.

OPTIONS:
  --root DIR     Identity directory (default ./misfin-data/identities)
  --store FILE   Mailbox database    (default ./misfin-data/mailbox.redb)
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

struct Flags {
    positional: Vec<String>,
    root: PathBuf,
    store: PathBuf,
    blurb: Option<String>,
    from: Option<String>,
    port: Option<u16>,
    pin: Option<String>,
    listen: Option<String>,
}

fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags {
        positional: Vec::new(),
        root: PathBuf::from("./misfin-data/identities"),
        store: PathBuf::from("./misfin-data/mailbox.redb"),
        blurb: None,
        from: None,
        port: None,
        pin: None,
        listen: None,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut take = |name: &str| {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--root" => flags.root = PathBuf::from(take("--root")?),
            "--store" => flags.store = PathBuf::from(take("--store")?),
            "--blurb" => flags.blurb = Some(take("--blurb")?),
            "--from" => flags.from = Some(take("--from")?),
            "--pin" => flags.pin = Some(take("--pin")?),
            "--listen" => flags.listen = Some(take("--listen")?),
            "--port" => {
                flags.port = Some(
                    take("--port")?
                        .parse()
                        .map_err(|_| "--port needs a number".to_string())?,
                )
            }
            other if other.starts_with("--") => return Err(format!("Unknown flag {other}")),
            other => flags.positional.push(other.to_string()),
        }
    }
    Ok(flags)
}

fn spec_for(address: &str, blurb: Option<String>) -> Result<MisfinIdentitySpec, String> {
    Ok(MisfinIdentitySpec {
        address: MisfinAddress::parse(address)?,
        blurb,
    })
}

fn run(args: Vec<String>) -> Result<(), String> {
    let Some((command, rest)) = args.split_first() else {
        return Err(USAGE.to_string());
    };
    let flags = parse_flags(rest)?;

    match command.as_str() {
        "id" => {
            let [address] = flags.positional.as_slice() else {
                return Err("usage: misfin id <mailbox@host> [--blurb TEXT] [--root DIR]".into());
            };
            let spec = spec_for(address, flags.blurb.clone())?;
            let status = ensure_identity_with_root(&spec, &flags.root)?;
            println!("address:     {}", status.address);
            if let Some(blurb) = &status.blurb {
                println!("blurb:       {blurb}");
            }
            if let Some(path) = &status.path {
                println!("stored at:   {}", path.display());
            }
            if let Some(fingerprint) = &status.certificate_fingerprint {
                println!("fingerprint: {fingerprint}");
            }
            Ok(())
        }
        "send" => {
            let Some((recipient, message_parts)) = flags.positional.split_first() else {
                return Err(
                    "usage: misfin send <recipient@host> <message...> --from <mailbox@host>".into(),
                );
            };
            if message_parts.is_empty() {
                return Err("misfin send: the message is empty".into());
            }
            let from = flags
                .from
                .as_deref()
                .ok_or("misfin send: --from <mailbox@host> is required")?;
            let recipient = MisfinAddress::parse(recipient)?;
            let message = message_parts.join(" ");
            let spec = spec_for(from, flags.blurb.clone())?;
            let identity = identity_material_with_root(&spec, &flags.root)?;
            let options = SendOptions {
                identity: Some(identity),
                port: flags.port,
                expected_fingerprint: flags.pin.clone(),
                ..Default::default()
            };
            let receipt = tokio_block_on(async {
                send(&recipient, &message, &options)
                    .await
                    .map_err(send_error_message)
            })?;
            println!("{} {}", receipt.status, receipt.meta);
            println!("server fingerprint: {}", receipt.server_fingerprint);
            if !receipt.status.is_success() {
                return Err(format!("delivery failed: {}", receipt.status));
            }
            Ok(())
        }
        "serve" => {
            if flags.positional.is_empty() {
                return Err(
                    "usage: misfin serve <mailbox@host> [<mailbox@host>...] [--store FILE] [--listen ADDR:PORT]"
                        .into(),
                );
            }
            let mut served = Vec::new();
            let mut server_identity = None;
            for (index, mailbox) in flags.positional.iter().enumerate() {
                let spec = spec_for(mailbox, flags.blurb.clone())?;
                let material = identity_material_with_root(&spec, &flags.root)?;
                let fingerprint = misfin::certificate_fingerprint(&material.certificate_der);
                served.push(ServedMailbox {
                    address: spec.address.clone(),
                    fingerprint,
                });
                if index == 0 {
                    server_identity = Some(material);
                }
            }
            let host = &served[0].address.host;
            if let Some(mismatched) = served.iter().find(|mailbox| &mailbox.address.host != host) {
                return Err(format!(
                    "misfin serve: all mailboxes must share one host ({} vs {host})",
                    mailbox_host(mismatched)
                ));
            }
            let identity = server_identity.expect("first mailbox minted");
            let listen: SocketAddr = flags
                .listen
                .as_deref()
                .unwrap_or("0.0.0.0:1958")
                .parse()
                .map_err(|_| "misfin serve: --listen needs ADDR:PORT".to_string())?;

            let store = MailboxStore::open(&flags.store).map_err(|error| error.to_string())?;
            let config = MisfinServerConfig::new(
                identity.certificate_der,
                identity.private_key_pkcs8_der,
                served,
            );
            let server = MisfinServer::new(config, store).map_err(|error| error.to_string())?;

            tokio_block_on(async move {
                let bound = server
                    .bind(listen)
                    .await
                    .map_err(|error| error.to_string())?;
                let addr = bound.local_addr().map_err(|error| error.to_string())?;
                eprintln!("misfin: serving on {addr} (ctrl-c to stop)");
                bound
                    .serve(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await
                    .map_err(|error| error.to_string())
            })
        }
        "inbox" => {
            let [mailbox] = flags.positional.as_slice() else {
                return Err("usage: misfin inbox <mailbox@host> [--store FILE]".into());
            };
            let store = MailboxStore::open(&flags.store).map_err(|error| error.to_string())?;
            let messages = store.list(mailbox).map_err(|error| error.to_string())?;
            if messages.is_empty() {
                println!("(no mail for {mailbox})");
                return Ok(());
            }
            for message in messages {
                let sender = message
                    .sender_address
                    .unwrap_or_else(|| format!("fingerprint {}", message.sender_fingerprint));
                println!("#{} @{} < {sender}", message.seq, message.received_at);
                for line in message.body.lines() {
                    println!("  {line}");
                }
            }
            Ok(())
        }
        "--help" | "-h" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(format!("Unknown command '{other}'.\n\n{USAGE}")),
    }
}

fn mailbox_host(mailbox: &ServedMailbox) -> &str {
    &mailbox.address.host
}

fn send_error_message(error: misfin::SendError) -> String {
    let mut message = error.to_string();
    if let misfin::SendError::WholeSendTimeout {
        receipt: Some(receipt),
    } = error
    {
        // The CLI converts errors to text, so retain the known reply here too.
        message.push_str(&format!(
            "\nserver reply: {} {}\nserver fingerprint: {}",
            receipt.status, receipt.meta, receipt.server_fingerprint
        ));
    }
    message
}

fn tokio_block_on<T>(
    future: impl std::future::Future<Output = Result<T, impl ToString>>,
) -> Result<T, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?
        .block_on(future)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_known_server_reply_survives_cli_error_formatting() {
        let fingerprint = "ab".repeat(32);
        let message = super::send_error_message(misfin::SendError::WholeSendTimeout {
            receipt: Some(misfin::SendReceipt {
                status: misfin::MisfinStatus::Delivered,
                meta: "known mailbox fingerprint".into(),
                server_fingerprint: fingerprint.clone(),
            }),
        });
        assert!(message.contains("server reply: 20 (message delivered) known mailbox fingerprint"));
        assert!(message.contains(&format!("server fingerprint: {fingerprint}")));
        assert_eq!(
            super::send_error_message(misfin::SendError::Timeout("response read")),
            "misfin response read timed out"
        );
    }
}
