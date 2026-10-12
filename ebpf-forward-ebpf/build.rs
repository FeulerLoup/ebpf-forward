use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary; rebuild whenever
/// the binary found on $PATH changes.
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}
