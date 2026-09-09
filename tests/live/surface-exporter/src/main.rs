fn main() {
    match cortex::surfaces::export_json() {
        Ok(contract) => println!("{contract}"),
        Err(error) => {
            eprintln!("failed to export compiled SurfaceContract: {error}");
            std::process::exit(1);
        }
    }
}
