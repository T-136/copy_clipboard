use miette::{ensure, Diagnostic, IntoDiagnostic, Result};
use thiserror::Error;

use clap::{Parser, Subcommand, ValueEnum};

use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    PublicKey, RsaPrivateKey, RsaPublicKey,
};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use clipboard::{ClipboardContext, ClipboardProvider};
use enigo::{Enigo, KeyboardControllable};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Error, Debug, Diagnostic)]
enum ConfigPathError {
    #[error("Path {} does not point to a file", target.display())]
    #[diagnostic(code(configpath::not_a_file), help("Check your --keyFile argument"))]
    TargetIsNotAFile { target: PathBuf },
    #[error("Could not get user config dir to create config file in")]
    #[diagnostic(
        code(configpath::user_config_dir),
        help("Try running without --userConfigDir or specify a path using --keyFile")
    )]
    UserConfigDirNotFound,
    #[error("Could not create missing directories in config path")]
    #[diagnostic(
        code(configpath::create_dirs),
        help("Check the given --keyFile or try to create the directory manually")
    )]
    CreateMissingDirectories(#[from] std::io::Error),
}

#[derive(Error, Debug, Diagnostic)]
enum RSAKeyError {
    #[error("Path {} does not point to a valid key file", target.display())]
    #[diagnostic(code(rsakey::could_not_read), help("Check your --keyFile argument"))]
    ReadKeyFile { target: PathBuf },
    #[error("Path {} does point to an existing file or directory", target.display())]
    #[diagnostic(
        code(rsakey::file_exists),
        help("Remove file to regen or use another --keyFile argument")
    )]
    FileExists { target: PathBuf },
    #[error("Failed to generate RSA key")]
    #[diagnostic(code(rsakey::keygen), help("Try again!"))]
    Keygen(#[source] rsa::errors::Error),
    #[error("Could not write key to file")]
    #[diagnostic(
        code(rsakey::write),
        help("Check your --keyFile argument or try again!")
    )]
    Write(#[source] rsa::pkcs8::Error),
    #[error("Could not encode key into pem format.")]
    #[diagnostic(
        code(rsakey::pem_encoding),
        help("Check your --keyFile argument, the provided public key or try again!")
    )]
    PemEnconding(#[source] rsa::pkcs8::spki::Error),
    #[error("Could not decode key from pem format.")]
    #[diagnostic(
        code(rsakey::pem_decoding),
        help("Check your --keyFile argument, the provided public key or try again!")
    )]
    PemDecoding(#[source] rsa::pkcs8::spki::Error),
    #[error("Could not encrypt contents")]
    #[diagnostic(code(rsakey::encrypt), help("Contact the developer or try again!"))]
    Encrypt(#[source] rsa::errors::Error),
    #[error("Could not decrypt contents")]
    #[diagnostic(code(rsakey::decrypt), help("Contact the developer or try again!"))]
    Decrypt(#[source] rsa::errors::Error),
}

#[derive(Error, Debug, Diagnostic)]
#[error("Could not decode base64 data.")]
#[diagnostic(code(base64_decode), help("Check the provided public key"))]
struct Base64DecodeError(#[from] base64::DecodeError);

#[derive(Error, Debug, Diagnostic)]
#[error("Could not decode u8 vec to utf-8 data.")]
#[diagnostic(code(base64_decode), help("Check the provided public key"))]
struct UTF8DecodeError(#[from] std::string::FromUtf8Error);

#[derive(Error, Debug, Diagnostic)]
enum NetworkingError {
    #[error("Could not serialize clipboard data")]
    #[diagnostic(code(networking::serialization), help("Contact the developer"))]
    Serialization(serde_json::Error),
    #[error("Could not send request")]
    #[diagnostic(
        code(networking::send_request),
        help("Ensure the server is running and check your --server argument")
    )]
    SendRequest(reqwest::Error),
    #[error("Could not read the response")]
    #[diagnostic(code(networking::read_response), help("Check your --server argument"))]
    ReadResponse(reqwest::Error),
}

#[derive(Error, Debug, Diagnostic)]
enum ClipboardError {
    #[error("Could not get the clpboard provider")]
    #[diagnostic(code(clipboard::provider), help("Contact the developer"))]
    GetProvider,
    #[error("Could not get clipboard contents")]
    #[diagnostic(
        code(clipboard::contents),
        help("Ensure the clipboard is not empty and try again")
    )]
    GetClipboard,
    #[error("Could not set clipboard contents")]
    #[diagnostic(
        code(clipboard::contents),
        help("Contact the developer or try using the print option instead")
    )]
    SetClipboard,
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey {
            key_file_path,
            use_user_config_dir,
        } => generate_key(get_key_file(key_file_path, use_user_config_dir)?)?,

        Commands::GetPublicKey {
            key_file_path,
            use_user_config_dir,
        } => print_public_key(get_private_key(get_key_file(
            key_file_path,
            use_user_config_dir,
        )?)?)?,

        Commands::Send {
            pub_key,
            server_url,
        } => send_clipboard(&pub_key, &server_url).await?,

        Commands::Receive {
            key_file_path,
            use_user_config_dir,
            server_url,
            action,
        } => {
            let key_file = get_key_file(key_file_path, use_user_config_dir)?;

            let clipboard_contents = receive_clipboard(key_file, &server_url).await?;

            match action {
                ReceiveAction::SetClipboard => {
                    // FIXME: currently not working, idk why
                    set_clipboard(&clipboard_contents)?;
                }
                ReceiveAction::Type => {
                    type_clipboard(&clipboard_contents);
                }
                ReceiveAction::Print => {
                    println!("{}", clipboard_contents);
                }
            }
        }
    };

    Ok(())
}

fn get_key_file(
    key_file_path: Option<String>,
    use_user_config_dir: bool,
) -> Result<std::path::PathBuf> {
    let config_dir = match dirs::config_dir() {
        Some(path) => path,
        None => {
            return Err(ConfigPathError::UserConfigDirNotFound)?;
        }
    };

    let parsed_path = match key_file_path {
        Some(path_string) => {
            let path = PathBuf::from(&path_string);

            if path.is_relative() && use_user_config_dir {
                config_dir.join("soren_copy_clipboard").join(path)
            } else {
                path
            }
        }
        None => config_dir
            .join("soren_copy_clipboard")
            .join("pubkey_keyfile"),
    };

    ensure!(
        parsed_path.file_name().is_some(),
        ConfigPathError::TargetIsNotAFile {
            target: parsed_path,
        },
    );

    match parsed_path.parent() {
        Some(p) => std::fs::create_dir_all(p)
            .or_else(|e| Err(ConfigPathError::CreateMissingDirectories(e)))?,
        _ => (),
    }

    Ok(parsed_path)
}

// fn parse_pubkey(pub_key: &str) -> Result<&RsaPublicKey> {
//     RsaPublicKey::from_public_key_der(&base64::decode(pub_key)?)?
// }

fn get_private_key(key_file: PathBuf) -> Result<RsaPrivateKey> {
    RsaPrivateKey::read_pkcs8_pem_file(&key_file)
        .or_else(|_| Err(RSAKeyError::ReadKeyFile { target: key_file })?)
}

fn generate_key(key_file: PathBuf) -> Result<()> {
    ensure!(
        !key_file.is_dir() && !key_file.exists(),
        RSAKeyError::FileExists { target: key_file }
    );

    let mut rng = rand::thread_rng();
    let private_key =
        RsaPrivateKey::new(&mut rng, 2048).or_else(|e| Err(RSAKeyError::Keygen(e)))?;

    private_key
        .write_pkcs8_pem_file(key_file, LineEnding::LF)
        .or_else(|e| Err(RSAKeyError::Write(e)))?;

    print_public_key(private_key)?;

    Ok(())
}

fn print_public_key(private_key: RsaPrivateKey) -> Result<()> {
    let public_key = RsaPublicKey::from(&private_key);

    println!(
        "Public key: \n\n{}",
        base64::encode(
            public_key
                .to_public_key_pem(LineEnding::LF)
                .or_else(|e| Err(RSAKeyError::PemEnconding(e)))?
        )
    );

    Ok(())
}

fn decode_public_key(pub_key: &str) -> Result<RsaPublicKey> {
    let pem_encoded_key = base64::decode(pub_key).or_else(|e| Err(Base64DecodeError(e)))?;

    let pem_encoded_key_as_string = String::from_utf8(pem_encoded_key).into_diagnostic()?;

    Ok(
        RsaPublicKey::from_public_key_pem(&pem_encoded_key_as_string)
            .or_else(|e| Err(RSAKeyError::PemDecoding(e)))?,
    )
}

fn get_public_key_hash(key: &RsaPublicKey) -> Result<String> {
    Ok(base64::encode(Sha256::digest(
        key.to_public_key_pem(LineEnding::LF)
            .or_else(|e| Err(RSAKeyError::PemEnconding(e)))?,
    )))
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Paste {
    id: String,
    text: String,
}

async fn send_clipboard(pub_key: &str, server_url: &str) -> Result<()> {
    let public_key = decode_public_key(pub_key)?;

    let id = get_public_key_hash(&public_key)?;

    let mut clipboard_provider =
        ClipboardContext::new().or_else(|_| Err(ClipboardError::GetProvider))?;

    let clipboard_contents = clipboard_provider
        .get_contents()
        .or_else(|_| Err(ClipboardError::GetClipboard))?;

    let mut rng = rand::thread_rng();

    let encrypted_clipboard = public_key
        .encrypt(
            &mut rng,
            rsa::padding::PaddingScheme::PKCS1v15Encrypt,
            &clipboard_contents.as_bytes(),
        )
        .or_else(|e| Err(RSAKeyError::Encrypt(e)))?;

    let client = reqwest::Client::new();
    client
        .post(format!("{}{}", server_url, "set_clipboard_text"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string::<Paste>(&Paste {
                id: id.to_owned(),
                text: base64::encode(encrypted_clipboard),
            })
            .or_else(|e| Err(NetworkingError::Serialization(e)))?,
        )
        .send()
        .await
        .or_else(|e| Err(NetworkingError::SendRequest(e)))?
        .text()
        .await
        .or_else(|e| Err(NetworkingError::ReadResponse(e)))?;

    Ok(())
}

async fn receive_clipboard(key_file: PathBuf, server_url: &str) -> Result<String> {
    let private_key = get_private_key(key_file)?;

    let public_key = RsaPublicKey::from(&private_key);

    let id = get_public_key_hash(&public_key)?;

    let body = reqwest::get(format!(
        "{}get_clipboard_text/{}",
        server_url,
        urlencoding::encode(id.as_str())
    ))
    .await
    .or_else(|e| Err(NetworkingError::SendRequest(e)))?
    .text()
    .await
    .or_else(|e| Err(NetworkingError::ReadResponse(e)))?;

    let clipboard = base64::decode(body).into_diagnostic()?;

    let clipboard_contents = private_key
        .decrypt(rsa::padding::PaddingScheme::PKCS1v15Encrypt, &clipboard)
        .or_else(|e| Err(RSAKeyError::Decrypt(e)))?;

    Ok(String::from_utf8(clipboard_contents).into_diagnostic()?)
}

fn set_clipboard(contents: &String) -> Result<()> {
    let mut clipboard_provider =
        ClipboardContext::new().or_else(|_| Err(ClipboardError::GetProvider))?;

    clipboard_provider
        .set_contents(contents.to_owned())
        .or_else(|_| Err(ClipboardError::SetClipboard))?;

    Ok(())
}

fn type_clipboard(contents: &String) -> () {
    let mut enigo = Enigo::new();
    enigo.key_sequence(contents.as_str());
}
