//! The `mycellium-desktop` binary: launch the egui client, or (without the `gui`
//! feature) a stub, so the controller can be built and tested headlessly.

#[cfg(feature = "gui")]
fn main() -> eframe::Result<()> {
    mycellium_desktop::ui::run()
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("mycellium-desktop was built without the `gui` feature (controller only).");
}
