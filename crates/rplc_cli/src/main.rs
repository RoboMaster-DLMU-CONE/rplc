use std::{fs, path::PathBuf, process};

use anyhow::Result;
use clap::Parser;
use miette::{Context, IntoDiagnostic, NamedSource, Report};
use rplc_core::{Severity, generate, validate};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(value_name = "FILE")]
    input: PathBuf,

    #[arg(short, long, value_name = "DIR")]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    miette::set_panic_hook();

    let args = Args::parse();

    let src_content = fs::read_to_string(&args.input)
        .into_diagnostic()
        .with_context(|| format!("无法读取文件: {:?}", args.input))
        .unwrap();

    let diagnostics = validate(&src_content);

    let mut has_errors = false;

    if !diagnostics.is_empty() {
        let source_code = NamedSource::new(args.input.to_string_lossy(), src_content.clone());
        println!("检测到 {} 个问题:", diagnostics.len());
        for diag in diagnostics {
            if diag.severity == Severity::Error {
                has_errors = true;
            }

            let report = Report::new(diag).with_source_code(source_code.clone());

            println!("{:?}", report);
        }
    }

    if has_errors {
        eprintln!("\n 生成终止");
        process::exit(1);
    }

    println!("\n正在生成代码...");

    let cpp_output = generate(&src_content)
        .map_err(|e| anyhow::anyhow!("代码生成失败: {}", e))
        .unwrap();

    let output_path = determine_output_path(&args.input, args.output.as_ref());

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .into_diagnostic()
            .with_context(|| format!("无法创建目录: {:?}", parent))
            .unwrap();
    }
    fs::write(&output_path, cpp_output)
        .into_diagnostic()
        .with_context(|| format!("无法写入文件: {:?}", output_path))
        .unwrap();
    println!("生成成功: {:?}", output_path);

    Ok(())
}

fn determine_output_path(input: &PathBuf, output_dir: Option<&PathBuf>) -> PathBuf {
    let file_stem = input.file_stem().unwrap_or_default();
    let new_filename = format!("{}.hpp", file_stem.to_string_lossy());

    match output_dir {
        Some(dir) => dir.join(new_filename),
        None => input.with_file_name(new_filename),
    }
}
