use anyhow::Result;
use clipboard::{ClipboardContext, ClipboardProvider};
use enigo::{Enigo, KeyboardControllable};
// use log;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    PublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
// use std::error::Error;
use rsa::{RsaPrivateKey, RsaPublicKey};

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

const SERVER_URL: &'static str = "http://localhost:8000/";

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ReceiveAction {
    SetClipboard,
    Type,
    Print,
}

#[derive(Subcommand, Debug)]
enum Commands {
    GenerateKey {
        #[clap(short = 'k', long = "keyFile", value_parser)]
        /// The file to save the private key to
        key_file_path: Option<String>,
        #[clap(short = 'u', long = "userConfigDir", action)]
        /// Use the user config directory as root instead of the current directory
        use_user_config_dir: bool,
    },
    GetPublicKey {
        #[clap(short = 'k', long = "keyFile", value_parser)]
        /// The file of the private key
        key_file_path: Option<String>,
        #[clap(short = 'u', long = "userConfigDir", action)]
        /// Use the user config directory as root instead of the current directory
        use_user_config_dir: bool,
    },
    Send {
        #[clap(value_parser)]
        /// The public key of the receiver
        pub_key: String,
        #[clap(short = 's', long= "serverURL", default_value_t=SERVER_URL.to_owned(),  value_parser)]
        /// The server to use
        server_url: String,
    },
    Receive {
        #[clap(short = 'k', long = "keyFile", value_parser)]
        /// The file of the private key
        key_file_path: Option<String>,
        #[clap(short = 'u', long = "userConfigDir", action)]
        /// Use the user config directory as root instead of the current directory
        use_user_config_dir: bool,
        #[clap(short = 's', long= "serverURL", default_value_t=SERVER_URL.to_owned(),  value_parser)]
        /// The server to use
        server_url: String,
        #[clap(arg_enum, default_value_t=ReceiveAction::Print, value_parser )]
        /// Should the local clipboard be set to the received value?
        action: ReceiveAction,
    },
}

macro_rules! print_errors_and_return {
    ($x:expr) => {
        match $x {
            Ok(a) => a,
            Err(b) => {
                println!("Error: {}", b);
                return;
            }
        }
    };
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey {
            key_file_path,
            use_user_config_dir,
        } => {
            let key_file =
                print_errors_and_return!(get_key_file(key_file_path, use_user_config_dir));

            print_errors_and_return!(generate_key(key_file));
        }
        Commands::GetPublicKey {
            key_file_path,
            use_user_config_dir,
        } => {
            let key_file =
                print_errors_and_return!(get_key_file(key_file_path, use_user_config_dir));

            print_errors_and_return!(print_public_key(print_errors_and_return!(get_private_key(
                key_file
            ))));
        }
        Commands::Send {
            pub_key,
            server_url,
        } => {
            print_errors_and_return!(send_clipboard(&pub_key, &server_url).await);
        }
        Commands::Receive {
            key_file_path,
            use_user_config_dir,
            server_url,
            action,
        } => {
            let key_file =
                print_errors_and_return!(get_key_file(key_file_path, use_user_config_dir));

            let clipboard_contents =
                print_errors_and_return!(receive_clipboard(key_file, &server_url).await);

            match action {
                ReceiveAction::SetClipboard => {
                    // FIXME: currently not working, idk why
                    print_errors_and_return!(set_clipboard(&clipboard_contents));
                }
                ReceiveAction::Type => {
                    type_clipboard(&clipboard_contents);
                }
                ReceiveAction::Print => {
                    println!("{}", clipboard_contents);
                }
            }
        }
    }
}

fn get_key_file(
    key_file_path: Option<String>,
    use_user_config_dir: bool,
) -> Result<std::path::PathBuf, &'static str> {
    let config_dir = match dirs::config_dir() {
        Some(path) => path,
        None => {
            return Err("Could not find config directory");
        }
    };

    let parsed_path = match key_file_path {
        Some(path_string) => {
            let path = PathBuf::from(&path_string);

            if path.is_relative() && use_user_config_dir {
                config_dir.join(path)
            } else {
                path
            }
        }
        None => config_dir
            .join("soren_copy_clipboard")
            .join("pubkey_keyfile"),
    };

    if parsed_path.file_name().is_none() {
        return Err("Invalid file path, pointing at directory");
    }

    match parsed_path
        .parent()
        .map(|parent| std::fs::create_dir_all(parent))
    {
        Some(v) => match v {
            Err(_) => return Err("Could not create directory"),
            _ => (),
        },
        _ => (),
    }

    Ok(parsed_path)
}

// fn parse_pubkey(pub_key: &str) -> Result<&RsaPublicKey> {
//     RsaPublicKey::from_public_key_der(&base64::decode(pub_key)?)?
// }

fn get_private_key(key_file: PathBuf) -> Result<RsaPrivateKey, &'static str> {
    RsaPrivateKey::read_pkcs8_pem_file(key_file).map_err(|_| "Could not read key file")
}

fn generate_key(key_file: PathBuf) -> Result<(), String> {
    if key_file.is_file() {
        return Err(format!(
            "Key file already exists: {}",
            key_file.display().to_string()
        ));
    }

    let mut rng = rand::thread_rng();
    let private_key = match RsaPrivateKey::new(&mut rng, 2048) {
        Ok(key) => key,
        Err(_) => return Err("Could not generate key".to_owned()),
    };

    match private_key.write_pkcs8_pem_file(key_file, LineEnding::LF) {
        Ok(_) => (),
        Err(_) => return Err("Could not write key to file".to_owned()),
    };

    match print_public_key(private_key) {
        Ok(_) => (),
        Err(e) => return Err(e.to_owned()),
    };

    Ok(())
}

fn print_public_key(private_key: RsaPrivateKey) -> Result<(), &'static str> {
    let public_key = RsaPublicKey::from(&private_key);

    println!(
        "Public key: \n\n{}",
        match public_key.to_public_key_pem(LineEnding::LF) {
            Ok(key) => base64::encode(key),
            Err(_) => return Err("Could not encode public key"),
        }
    );

    Ok(())
}

fn decode_public_key(pub_key: &str) -> Result<RsaPublicKey, &'static str> {
    let pem_encoded_key = match base64::decode(pub_key) {
        Ok(key) => key,
        Err(_) => return Err("Could not decode public key, failed to parse base64"),
    };

    let pem_encoded_key_as_string = match String::from_utf8(pem_encoded_key) {
        Ok(key) => key,
        Err(_) => return Err("Could not decode public key, failed to parse utf8"),
    };

    Ok(
        match RsaPublicKey::from_public_key_pem(&pem_encoded_key_as_string) {
            Ok(key) => key,
            Err(_) => return Err("Could not decode public key, not valid pem"),
        },
    )
}

fn get_public_key_hash(key: &RsaPublicKey) -> Result<String, &'static str> {
    Ok(base64::encode(Sha256::digest(
        match key.to_public_key_pem(LineEnding::LF) {
            Ok(key) => key,
            Err(_) => return Err("Could not encode public key"),
        },
    )))
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Paste {
    id: String,
    text: String,
}

async fn send_clipboard(pub_key: &str, server_url: &str) -> Result<(), &'static str> {
    let public_key = match decode_public_key(pub_key) {
        Ok(key) => key,
        Err(e) => return Err(e),
    };

    let id = get_public_key_hash(&public_key)?;

    let mut clipboard_provider = match ClipboardContext::new() {
        Ok(provider) => provider,
        Err(_) => return Err("Could not get clipboard provider"),
    };

    let clipboard_contents = match clipboard_provider.get_contents() {
        Ok(contents) => contents,
        Err(_) => return Err("Could not get clipboard contents"),
    };

    let mut rng = rand::thread_rng();

    let encrypted_clipboard = match public_key.encrypt(
        &mut rng,
        rsa::padding::PaddingScheme::PKCS1v15Encrypt,
        &clipboard_contents.as_bytes(),
    ) {
        Ok(encrypted) => encrypted,
        Err(_) => return Err("Could not encrypt clipboard contents"),
    };

    let client = reqwest::Client::new();
    match match client
        .post(format!("{}{}", server_url, "set_clipboard_text"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            match serde_json::to_string::<Paste>(&Paste {
                id: id.to_owned(),
                text: base64::encode(encrypted_clipboard),
            }) {
                Ok(body) => body,
                Err(_) => return Err("Could not serialize body"),
            },
        )
        .send()
        .await
    {
        Ok(body) => body,
        Err(_) => return Err("Could not send request"),
    }
    .text()
    .await
    {
        Ok(body) => body,
        Err(_) => return Err("Could not read response"),
    };

    Ok(())
}

async fn receive_clipboard(key_file: PathBuf, server_url: &str) -> Result<String, &'static str> {
    let private_key = match get_private_key(key_file) {
        Ok(key) => key,
        Err(e) => return Err(e),
    };

    let public_key = RsaPublicKey::from(&private_key);

    let id = get_public_key_hash(&public_key)?;

    let body = match match reqwest::get(format!(
        "{}get_clipboard_text/{}",
        server_url,
        urlencoding::encode(id.as_str())
    ))
    .await
    {
        Ok(body) => body,
        Err(_) => return Err("Could not send request"),
    }
    .text()
    .await
    {
        Ok(body) => body,
        Err(_) => return Err("Could not read response"),
    };

    let clipboard = match base64::decode(body) {
        Ok(clipboard) => clipboard,
        Err(_) => return Err("Could not decode clipboard"),
    };

    let clipboard_contents =
        match private_key.decrypt(rsa::padding::PaddingScheme::PKCS1v15Encrypt, &clipboard) {
            Ok(contents) => contents,
            Err(_) => return Err("Could not decrypt clipboard"),
        };

    Ok(match String::from_utf8(clipboard_contents) {
        Ok(contents) => contents,
        Err(_) => return Err("Could not decode clipboard"),
    })
}

fn set_clipboard(contents: &String) -> Result<(), &'static str> {
    let mut clipboard_provider = match ClipboardContext::new() {
        Ok(provider) => provider,
        Err(_) => return Err("Could not get clipboard provider"),
    };

    match clipboard_provider.set_contents(contents.to_owned()) {
        Ok(_) => (),
        Err(_) => return Err("Could not set clipboard contents"),
    };

    Ok(())
}

fn type_clipboard(contents: &String) -> () {
    let mut enigo = Enigo::new();
    enigo.key_sequence(contents.as_str());
}
