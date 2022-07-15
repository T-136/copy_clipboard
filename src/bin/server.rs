use std::{
    collections::{HashMap},
    sync::{Mutex},
};

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};

#[get("/get_clipboard_text/{id}")]
async fn get_clipboard_text(
    id: web::Path<String>,

    data: web::Data<Mutex<HashMap<String, String>>>, // values: Mutex<HashMap<String, String>>,
) -> impl Responder {
    println!("{:?}", id.as_str());
    let hashmap = data.lock().unwrap();
    println!("{:?}", hashmap);
    let value = hashmap.get(id.as_str());
    match value {
        Some(val) => HttpResponse::Ok().body(val.clone()),
        None => HttpResponse::NotFound().body("not found bro"),
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Paste {
    id: String,
    text: String,
}
async fn set_clipboard_text(
    data: web::Data<Mutex<HashMap<String, String>>>, // values: Mutex<HashMap<String, String>>,
    req_body: web::Json<Paste>,
) -> impl Responder {
    println!("{:?}", req_body);
    let mut hashmap = data.lock().unwrap();
    if hashmap.contains_key(&req_body.id) {
        let value = hashmap.get_mut(&req_body.id).unwrap();
        *value = req_body.text.clone();
    } else {
        hashmap.insert(req_body.id.clone(), req_body.text.clone());
    }

    HttpResponse::Ok().body(req_body.text.clone())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let data: web::Data<Mutex<HashMap<String, String>>> =
        web::Data::new(Mutex::new(HashMap::new()));
    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .service(get_clipboard_text)
            .route("/set_clipboard_text", web::post().to(set_clipboard_text))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}