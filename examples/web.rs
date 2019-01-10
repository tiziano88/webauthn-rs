#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;

const INDEX_CONTENT: &str = include_str!("index.html");

#[get("/")]
fn index() -> &'static str {
    INDEX_CONTENT
}

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
