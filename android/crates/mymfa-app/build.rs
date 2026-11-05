fn main() {
    let config = slint_build::CompilerConfiguration::new()
        .with_include_paths(std::iter::once("ui".into()).collect())
        .with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/main.slint", config).unwrap();
}
