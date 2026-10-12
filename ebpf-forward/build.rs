use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "ebpf-forward-ebpf")
        .ok_or_else(|| anyhow!("ebpf-forward-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    // 编译 eBPF 需要 nightly；CI 用 EBPF_TOOLCHAIN 锁定日期版本（须与 bpf-linker 的 LLVM 匹配）
    println!("cargo:rerun-if-env-changed=EBPF_TOOLCHAIN");
    let pinned = std::env::var("EBPF_TOOLCHAIN")
        .ok()
        .filter(|t| !t.is_empty());
    let toolchain = match pinned.as_deref() {
        Some(t) => Toolchain::Custom(t),
        None => Toolchain::default(),
    };
    aya_build::build_ebpf([ebpf_package], toolchain)
}
