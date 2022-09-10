// #![allow(dead_code)]
// #![allow(unused)]
use anyhow::Result;
use enigo::*;
// use log;
use reqwest::header::CONTENT_TYPE;
use rsa::pkcs1::{EncodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, self, EncodePublicKey, DecodePrivateKey, DecodePublicKey};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::env;
// use std::error::Error;
use std::process::Command;
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, padding};

enum Option {
    Send,
    Receive,
    GenerateKey
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();


    let id = &args.get(1).expect("no id/ public key given");
    let option: Option;
    let arg = args.get(2).expect("give me send or receive pls");
    if arg == "send" {
        option = Option::Send;
    } else if arg == "receive" {
        option = Option::Receive;
    } else if arg == "generate" {
        option = Option::GenerateKey;
    } else {
        panic!("wrong second argument, send, generate or receive expected");
    }

    println!("{}", id);

    match option {
        Option::Send => match get_selected_text() {
            Ok(s) => println!("{:?}", send_clipboard(s, id).await),
            Err(e) => println!("{:?}", e),
        },

        Option::Receive => {
            let message = get_clipboard(id).await.unwrap();
            paste(&message)
        },
        Option::GenerateKey => {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        println!("{:?}", public_key);
        let _ = private_key.write_pkcs8_pem_file("test", pkcs8::LineEnding::LF);

        let pub_string = base64::encode(&public_key.to_public_key_der().unwrap());
        println!("{}",pub_string);
        }
    };

    // get_selected_text();
    // println!("{:?}", send_clipboard("text".to_string(), "id").await)
    // paste("test 1231 2312 3")
}

const SERVER_URL: &str = "http://127.0.0.1:8080/";

fn get_selected_text() -> Result<String> {
    let output = Command::new("xsel")
        // execute the command, wait for it to complete, then capture the output
        .output();

    let res = String::from_utf8(output?.stdout)?;
    Ok(res)
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Paste {
    id: String,
    text: String,
}

async fn send_clipboard(text: String, pub_key_as_base64: &str) -> Result<String> {

    let mut rng = rand::thread_rng();
    let pub_key_der = &base64::decode(&pub_key_as_base64).expect("couldn't decode public key from base64");
    let pub_key = RsaPublicKey::from_public_key_der(&pub_key_der).expect("invalid public key");
    let client = reqwest::Client::new();
    let body = client
        .post(format!("{}{}", SERVER_URL, "set_clipboard_text"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_string::<Paste>(&Paste {
            id: pub_key_as_base64.to_string(),
            text: String::from_utf8(pub_key.encrypt(&mut rng, rsa::padding::PaddingScheme::PKCS1v15Encrypt, &text.as_bytes()).unwrap()).unwrap(), 
        })?)
        .send()
        .await?
        .text()
        .await?;
    Ok(body)
}
async fn get_clipboard(id: &str) -> Result<String> {
    // TODO: read private key and encrypt clipboard

    let priv_key = RsaPrivateKey::from_pkcs8_pem("test").expect("no public key found/ couldn't read");
    let body = reqwest::get(format!("{}get_clipboard_text/{}", SERVER_URL, id))
        .await?
        .text()
        .await?;
    Ok(String::from_utf8(priv_key.decrypt(rsa::padding::PaddingScheme::PKCS1v15Encrypt, body.as_bytes()).expect("couldn't decode message with that pub key")).expect("could not convert to string"))
}

fn paste(text: &str) {
    let mut enigo = Enigo::new();
    enigo.key_sequence(text);
}

#[tokio::test]
async fn test_setting_and_getting_clipboard() {
    assert_eq!(
        "test 123",
        send_clipboard("test 123".to_string(), "123").await.unwrap()
    );
    assert_eq!("test 123", get_clipboard("123").await.unwrap());
}
