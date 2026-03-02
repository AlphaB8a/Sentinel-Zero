use anyhow::{anyhow, Context};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenSpec {
    Unix(PathBuf),
    Tcp(SocketAddr),
    TcpTls(SocketAddr),
}

impl ListenSpec {
    pub fn parse(spec: &str) -> anyhow::Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(anyhow!("listen spec is empty"));
        }
        if !spec.contains(':') && spec.starts_with('/') {
            return Ok(Self::Unix(PathBuf::from(spec)));
        }

        let (scheme, rest) = spec
            .split_once(':')
            .ok_or_else(|| anyhow!("listen spec missing scheme: {}", spec))?;
        let rest = rest.trim();

        match scheme {
            "unix" => {
                if rest.is_empty() {
                    return Err(anyhow!("unix listen spec missing path"));
                }
                Ok(Self::Unix(PathBuf::from(rest)))
            }
            "tcp" => {
                let addr = SocketAddr::from_str(rest)
                    .with_context(|| format!("invalid tcp listen address: {}", rest))?;
                Ok(Self::Tcp(addr))
            }
            "tcp+tls" | "tcps" => {
                let addr = SocketAddr::from_str(rest)
                    .with_context(|| format!("invalid tcp+tls listen address: {}", rest))?;
                Ok(Self::TcpTls(addr))
            }
            _ => Err(anyhow!("unsupported listen scheme: {}", scheme)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ListenSpec;

    #[test]
    fn parse_tcp_tls_spec() {
        let spec = ListenSpec::parse("tcp+tls:127.0.0.1:7777").expect("parse");
        match spec {
            ListenSpec::TcpTls(addr) => assert_eq!(addr.to_string(), "127.0.0.1:7777"),
            _ => panic!("expected TcpTls"),
        }
    }
}
