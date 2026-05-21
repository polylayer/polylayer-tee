//! In-enclave vsock-tunneled HTTP transport for the AWS SDK.
//!
//! ## Why this exists
//!
//! A Nitro enclave has no direct network and no DNS resolver. Every
//! egress hop has to go through the parent EC2's `vsock-proxy`, which
//! is a transparent TCP-over-vsock forwarder constrained to an
//! allowlist of AWS endpoints (`/etc/nitro_enclaves/vsock-proxy.yaml`).
//!
//! The trick is making the AWS SDK *think* it's talking directly to
//! AWS while the bytes actually tunnel through vsock. We compose four
//! pieces:
//!
//! 1. **Image-baked `/etc/hosts`** in the enclave maps every AWS
//!    hostname we care about (e.g. `kms.eu-central-1.amazonaws.com`)
//!    to `127.0.0.1`. The OS resolver inside the enclave goes through
//!    `getaddrinfo`, which honors `/etc/hosts`, so no DNS server is
//!    needed inside the enclave. See `deploy/enclave/etc-hosts`.
//!
//! 2. **Per-service `endpoint_url` override** in `bootstrap::from_env`.
//!    The SDK dials `kms.eu-central-1.amazonaws.com:8001` (resolves to
//!    127.0.0.1) instead of `:443`. The TLS handshake still uses the
//!    real hostname as SNI, so AWS's real certificate validates
//!    cleanly — `vsock-proxy` never terminates TLS.
//!
//! 3. **Localhost-to-vsock bridge tasks** (defined here) listen on
//!    `127.0.0.1:8001/8002/8003` inside the enclave and pipe each
//!    accepted TCP connection bidirectionally to `vsock://3:8001/2/3`.
//!    These bind early in `Storage::from_env`.
//!
//! 4. **`vsock-proxy` on the parent** listens on vsock CID 3, port
//!    8001/2/3 and forwards to the real AWS endpoint:443. The systemd
//!    units are in `deploy/cloud-init/parent-bootstrap.sh`.
//!
//! Credentials are a separate flow: the parent's `imds-bridge` vends
//! the EC2 instance-role STS creds as JSON on vsock CID 3, port 9000.
//! See `vsock_creds.rs`.

use crate::StorageError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, error, info, warn};

/// Parent EC2 vsock CID for Nitro enclaves. **This is 3, not 2.**
///
/// The Linux kernel's `VMADDR_CID_HOST` constant is 2 — that's the
/// generic "host" CID used by KVM/QEMU. AWS Nitro Enclaves assigns
/// the parent EC2 instance CID 3 (the kernel reserves 0–1 and uses 2
/// for the local hypervisor in some virt stacks but Nitro shifts it).
/// `tokio_vsock::VMADDR_CID_HOST` returns 2, which connects to the
/// wrong place from inside a Nitro enclave; we use a literal here.
///
/// See the AWS Nitro Enclaves user guide:
/// <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#term-encliddef>
pub const PARENT_CID: u32 = 3;

/// Vsock port on which the parent's vsock-proxy forwards to KMS:443.
pub const PORT_KMS: u32 = 8001;
/// Vsock port for S3:443.
pub const PORT_S3: u32 = 8002;
/// Vsock port for DynamoDB:443.
pub const PORT_DDB: u32 = 8003;
/// Vsock port on which the parent's imds-bridge vends STS creds JSON.
/// **Do not use 9000** — nitro-cli reserves it for the enclave boot
/// heartbeat vsock socket; binding it on the parent prevents
/// `nitro-cli run-enclave` from completing the handshake.
pub const PORT_CREDS: u32 = 9100;

// ─── localhost → vsock bridges ───────────────────────────────────────

/// Bind a TCP listener on `127.0.0.1:<local_port>` and pipe every
/// accepted connection bidirectionally to `vsock://PARENT_CID:<vsock_port>`.
///
/// Returns after the listener is bound; the accept loop is a spawned
/// task that runs for the lifetime of the process. If `accept` fails
/// permanently the task logs at `error!` and exits — the enclave then
/// has to restart to recover (acceptable for a stateless signing
/// service; systemd handles it).
pub async fn spawn_bridge(local_port: u16, vsock_port: u32) -> Result<(), StorageError> {
    let bind: SocketAddr = (IpAddr::V4(Ipv4Addr::LOCALHOST), local_port).into();
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| StorageError::Io(format!("bind 127.0.0.1:{local_port}: {e}")))?;
    info!(local_port, vsock_port, "vsock bridge listening");

    tokio::spawn(async move {
        loop {
            let (mut tcp, peer) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    error!(?e, local_port, "bridge accept failed; bridge task exiting");
                    return;
                }
            };
            debug!(?peer, local_port, vsock_port, "bridge accept");

            tokio::spawn(async move {
                let vsock_addr = VsockAddr::new(PARENT_CID, vsock_port);
                let mut vsock = match VsockStream::connect(vsock_addr).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(?e, vsock_port, "vsock connect failed");
                        let _ = tcp.shutdown().await;
                        return;
                    }
                };
                if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut vsock).await {
                    debug!(?e, "bridge copy ended");
                }
            });
        }
    });

    Ok(())
}

/// Spawn all three service bridges (KMS / S3 / DDB) on conventional
/// ports. Tasks run for the lifetime of the process.
pub async fn spawn_all_bridges() -> Result<(), StorageError> {
    spawn_bridge(PORT_KMS as u16, PORT_KMS).await?;
    spawn_bridge(PORT_S3 as u16, PORT_S3).await?;
    spawn_bridge(PORT_DDB as u16, PORT_DDB).await?;
    Ok(())
}

// ─── Per-service endpoint URLs ───────────────────────────────────────
//
// These match the ports used by the parent's vsock-proxy units. The
// SDK uses the hostname for SNI + cert validation (the AWS endpoint
// is honored end-to-end through the vsock-proxy TCP tunnel), but the
// IP resolution lands on 127.0.0.1 thanks to the enclave's baked-in
// /etc/hosts, and the port lands on our bridge.

pub fn kms_endpoint(region: &str) -> String {
    format!("https://kms.{region}.amazonaws.com:{PORT_KMS}")
}

pub fn s3_endpoint(region: &str) -> String {
    format!("https://s3.{region}.amazonaws.com:{PORT_S3}")
}

pub fn ddb_endpoint(region: &str) -> String {
    format!("https://dynamodb.{region}.amazonaws.com:{PORT_DDB}")
}
