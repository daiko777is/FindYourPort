fn main() {
    slint_build::compile("ui/app-window.slint").unwrap();
    println!("cargo:rerun-if-changed=ui/assets/tray-icon.png");
}
