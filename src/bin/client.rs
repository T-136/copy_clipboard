#![allow(dead_code)]
// #![allow(unused)]
use anyhow::Result;
use enigo::*;
// use log;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use std::env;
// use std::error::Error;
use std::process::Command;

enum Option {
    Send,
    Receive,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let id = &args[1];
    let option: Option;
    if &args[2] == "send" {
        option = Option::Send;
    } else if &args[2] == "receive" {
        option = Option::Receive;
    } else {
        panic!("wrong second argument, send or receive expected");
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

async fn send_clipboard(text: String, id: &str) -> Result<String> {
    //TODO: add id to string and post with text as body

    let client = reqwest::Client::new();
    let body = client
        .post(format!("{}{}", SERVER_URL, "set_clipboard_text"))
        .header(CONTENT_TYPE, "application/json")
        .body(serde_json::to_string::<Paste>(&Paste {
            id: id.to_string(),
            text: text,
        })?)
        .send()
        .await?
        .text()
        .await?;
    Ok(body)
}
async fn get_clipboard(id: &str) -> Result<String> {
    //TODO: add id to url
    let body = reqwest::get(format!("{}get_clipboard_text/{}", SERVER_URL, id))
        .await?
        .text()
        .await?;
    Ok(body)
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
