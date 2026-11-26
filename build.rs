fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=assets/deadwall.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/deadwall.ico")
            .compile()?;
    }
    Ok(())
}
