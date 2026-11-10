# l5-rust-wire

L5Droid 与 l5proxy-rust 共用的隧道协议库。Cargo 包名为 **l5-wire**，Rust 导入名为 **l5_wire**；GitHub 仓库可以命名为 **l5-rust-wire**。

## 范围

- L5 v2 帧头、命令、序号、长度及收发编解码。
- ring AES-128-GCM：头部始终加密认证；FULL payload 加密认证。
- TLS_PASSTHROUGH：仅对允许透传的应用密文跳过 payload 加密和认证；帧头仍须认证。不额外计算 payload MAC/GHASH。
- 按连接和方向维护轻量 TLS 记录识别状态，按长度跳过正文，不扫描整个 payload。
- Tokio/futures Sink、Stream，Bytes 所有权传递和可取消的流式解码。

本库不实现或依赖 rustls，不包含 WebSocket、lwIP、TUN、Android JNI 或服务器配置。特殊 TLS 的握手、记录层和硬件能力由调用方管理。

## 独立测试

```sh
cargo test --locked
cargo check --locked --all-targets
```

Cargo.lock 保留用于复现测试；target/ 不提交。publish=false 仅禁止误发 crates.io，不影响 Git 依赖。

## GitHub 依赖

仓库上传后，在客户端和服务端的 Cargo.toml 中引用相同的完整提交哈希：

```toml
[dependencies]
l5-wire = { git = "https://github.com/YOUR_ACCOUNT/l5-rust-wire.git", rev = "FULL_COMMIT_SHA" }
```

上面是说明模板，不是本库的构建配置。本库没有任何本地 path 依赖或 vendor patch。

## 与定制 TLS 对接

调用方保留自己的 vendor/rustls 和根清单中的 [patch.crates-io]。
原来依赖私有 rustls API 的小型适配器已移回双方的 src/tls_io.rs；使用：

```rust,ignore
let transport = l5_wire::transport::Transport::new_owned(
    tls, &root_key, is_client, crate::tls_io::poll_chunk,
)?;
```

new_owned 接受调用方提供的读取 Bytes 回调，不绑定 TLS 实现。普通 AsyncRead/AsyncWrite 可使用 Transport::new。拆分后不再有 tls feature；更新依赖时删除旧的 features=["tls"]。

接收透传 DATA 时可返回同一 L5 帧的多个有序 Bytes 切片，调用方应按 TCP 字节流消费。FULL 数据必须完整通过认证才交付。不完整尾包的处理和 TLS 接收 slab 回收属于调用方的 rustls 实现。

## 提交范围

提交 Cargo.toml、Cargo.lock、README.md、.gitignore、src/、tests/。此目录不含部署密钥、认证配置或服务端 vendor 源码。客户端和服务端的最终 Git URL/rev 接入待仓库创建后完成。
