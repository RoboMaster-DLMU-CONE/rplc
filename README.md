# RPLC - RPL Compiler

RPLC (RPL Compiler) 是一个基于 Rust 的包生成工具，专为 [RPL](https://github.com/RoboMaster-DLMU-CONE/rpl) 项目设计。它可以将 JSON 配置文件转换为标准化的 C++ 头文件，用于机器人通信包。

## 功能特点

- **JSON 配置**: 通过 JSON 文件定义包结构
- **代码生成**: 输出带有打包结构和包特性的 C++ 头文件
- **验证功能**: 根据 C++ 语法规则和最佳实践进行全面验证
- **跨平台支持**: 支持 Windows、Linux 和 macOS
- **WebAssembly 绑定**: 提供 Web 使用的 WASM 版本

## 安装

### 预编译二进制文件
从 [发布页面](https://github.com/RoboMaster-DLMU-CONE/rplc/releases) 下载最新版本。

### 源码编译
```bash
cargo build --release
```

## 使用方法

### 命令行工具使用
```bash
# 从 JSON 配置生成 C++ 头文件
./rplc config.json

# 指定输出目录
./rplc config.json --output ./output/
```

### WebAssembly 版本使用
WASM 版本允许你在浏览器或 Node.js 环境中直接使用 RPLC。

## JSON 配置格式

详情请参阅 [配置格式文档](doc/schema.md)。

## 架构

该项目采用多包工作区结构，包含三个主要组件：

- `rplc_core`: 核心生成和验证逻辑
- `rplc_cli`: 命令行界面
- `rplc_wasm`: WebAssembly 绑定

## 许可证

本项目采用 ICS 许可证 - 详情请见 LICENSE 文件。

## 贡献

欢迎提交拉取请求。
