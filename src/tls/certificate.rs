// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::identity::Identity;
use crate::tls::{Error, IdentityVerifier, OutboundConnector};
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use itertools::Itertools;
use std::{cmp, iter};

use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use rustls::{ClientConfig, CommonState, RootCertStore, ServerConfig};
use rustls_pemfile::Item;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::tls;
use x509_parser::certificate::X509Certificate;
use x509_parser::error::X509Result;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub expiry: Expiration,
    pub der: CertificateDer<'static>,
}

#[derive(Clone, Debug)]
pub struct Expiration {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

#[derive(Debug)]
pub struct WorkloadCertificate {
    /// cert is the leaf certificate
    pub cert: Certificate,
    /// chain is the entire trust chain, excluding the leaf and root
    pub chain: Vec<Certificate>,
    pub private_key: PrivateKeyDer<'static>,

    /// precomputed roots. This is used for verification
    root_store: Arc<RootCertStore>,
    /// original roots, used for debugging
    pub roots: Vec<Certificate>,
}

pub fn certificate_from_connection(conn: &CommonState) -> X509Result<'_, X509Certificate<'_>> {
    use x509_parser::prelude::*;
    conn.peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or(X509Error::InvalidCertificate.into())
        .and_then(|cert| {
            X509Certificate::from_der(cert).inspect_err(|e| warn!("invalid certificate: {e}"))
        })
}

pub fn identity(result: &X509Result<X509Certificate>) -> Option<Identity> {
    result
        .as_ref()
        .map_or(None, |(_, cert)| match identities(cert) {
            Ok(ids) => ids.into_iter().next(),
            Err(e) => {
                warn!("failed to extract identity: {}", e);
                None
            }
        })
}

pub fn identities(cert: &X509Certificate) -> Result<Vec<Identity>, Error> {
    use x509_parser::prelude::*;
    let names = cert
        .subject_alternative_name()?
        .map(|x| &x.value.general_names);

    let uris: Vec<_> = names
        .into_iter()
        .flatten()
        .filter_map(|name| match name {
            GeneralName::URI(uri) => Some(*uri),
            _ => None,
        })
        .collect();
    if uris.len() != 1 {
        return Err(Error::CertificateParseError(
            "expected exactly one URI SAN".into(),
        ));
    }
    let identity =
        Identity::from_str(uris[0]).map_err(|e| Error::CertificateParseError(e.to_string()))?;
    Ok(vec![identity])
}

impl Certificate {
    // TODO: I would love to parse this once, but ran into lifetime issues.
    fn parsed(&self) -> X509Certificate<'_> {
        x509_parser::parse_x509_certificate(&self.der)
            .expect("certificate was already parsed successfully before")
            .1
    }

    pub fn as_pem(&self) -> String {
        der_to_pem(&self.der, CERTIFICATE)
    }

    pub fn identity(&self) -> Option<Identity> {
        self.parsed()
            .subject_alternative_name()
            .ok()
            .flatten()
            .and_then(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::URI(uri) => Some(uri),
                        _ => None,
                    })
                    .next()
            })
            .and_then(|san| Identity::from_str(san).ok())
    }

    #[cfg(test)]
    pub fn names(&self) -> Vec<String> {
        let reg = oid_registry::OidRegistry::default().with_x509();

        self.parsed()
            .subject
            .iter()
            .flat_map(|dn| {
                dn.iter().map(|x| {
                    reg.get(x.attr_type()).unwrap().sn().to_string() + "/" + x.as_str().unwrap()
                })
            })
            .chain(
                self.parsed()
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .iter()
                    .flat_map(|ext| ext.value.general_names.iter().map(|n| n.to_string())),
            )
            .collect()
    }

    pub fn serial(&self) -> String {
        self.parsed().serial.to_string()
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn serial_bytes(&self) -> Vec<u8> {
        self.parsed().tbs_certificate.raw_serial().to_vec()
    }

    pub fn expiration(&self) -> Expiration {
        self.expiry.clone()
    }
}

fn expiration(cert: X509Certificate) -> Expiration {
    Expiration {
        not_before: UNIX_EPOCH
            + Duration::from_secs(
                cert.validity
                    .not_before
                    .timestamp()
                    .try_into()
                    .unwrap_or_default(),
            ),
        not_after: UNIX_EPOCH
            + Duration::from_secs(
                cert.validity
                    .not_after
                    .timestamp()
                    .try_into()
                    .unwrap_or_default(),
            ),
    }
}

pub fn parse_cert(mut cert: Vec<u8>) -> Result<Certificate, Error> {
    let mut reader = std::io::BufReader::new(Cursor::new(&mut cert));
    let parsed = rustls_pemfile::read_one(&mut reader)
        .map_err(|e| Error::CertificateParseError(e.to_string()))?
        .ok_or_else(|| Error::CertificateParseError("no certificate".to_string()))?;
    let Item::X509Certificate(der) = parsed else {
        return Err(Error::CertificateParseError("no certificate".to_string()));
    };

    let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
    Ok(Certificate {
        der: der.clone(),
        expiry: expiration(cert),
    })
}

fn parse_cert_multi(mut cert: &[u8]) -> Result<Vec<Certificate>, Error> {
    let mut reader = std::io::BufReader::new(Cursor::new(&mut cert));
    let parsed: Result<Vec<_>, _> = rustls_pemfile::read_all(&mut reader).collect();
    parsed
        .map_err(|e| Error::CertificateParseError(e.to_string()))?
        .into_iter()
        .map(|p| {
            let Item::X509Certificate(der) = p else {
                return Err(Error::CertificateParseError("no certificate".to_string()));
            };
            let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
            Ok(Certificate {
                der: der.clone(),
                expiry: expiration(cert),
            })
        })
        .collect()
}

fn parse_key(mut key: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    let mut reader = std::io::BufReader::new(Cursor::new(&mut key));
    let parsed = rustls_pemfile::read_one(&mut reader)
        .map_err(|e| Error::CertificateParseError(e.to_string()))?
        .ok_or_else(|| Error::CertificateParseError("no key".to_string()))?;
    match parsed {
        Item::Pkcs8Key(c) => Ok(PrivateKeyDer::Pkcs8(c)),
        _ => Err(Error::CertificateParseError("no key".to_string())),
    }
}

impl WorkloadCertificate {
    pub fn new(key: &[u8], cert: &[u8], chain: Vec<&[u8]>) -> Result<WorkloadCertificate, Error> {
        let cert = parse_cert(cert.to_vec())?;

        // The Istio API does something pretty unhelpful, by providing a single chain of certs.
        // The last one is the root. However, there may be multiple roots concatenated in that last cert,
        // so we will need to split them.
        let Some(raw_root) = chain.last() else {
            return Err(Error::InvalidRootCert(
                "no root certificate present".to_string(),
            ));
        };
        let roots = parse_cert_multi(raw_root)?;
        let chain = chain[..cmp::max(0, chain.len() - 1)]
            .iter()
            .map(|x| x.to_vec())
            .map(parse_cert)
            .collect::<Result<Vec<_>, _>>()?;
        let key: PrivateKeyDer = parse_key(key)?;

        let mut roots_store = RootCertStore::empty();
        let (_valid, invalid) =
            roots_store.add_parsable_certificates(roots.iter().map(|c| c.der.clone()));
        if invalid > 0 {
            tracing::warn!("warning: found {invalid} invalid root certs");
        }
        Ok(WorkloadCertificate {
            cert,
            chain,
            private_key: key,
            roots,
            root_store: Arc::new(roots_store),
        })
    }

    pub fn identity(&self) -> Option<Identity> {
        self.cert.identity()
    }

    /// The trust anchors this certificate chains to. Used to re-run the shared webpki
    /// chain-validation path ([`crate::tls::revocation::verify_cert_chain`]) against a peer chain
    /// captured at handshake time, e.g. to re-check CRL revocation on an existing connection.
    pub fn root_store(&self) -> Arc<RootCertStore> {
        self.root_store.clone()
    }

    // TODO: can we precompute some or all of this?

    pub(in crate::tls) fn cert_and_intermediates_der(&self) -> Vec<CertificateDer<'static>> {
        std::iter::once(self.cert.der.clone())
            .chain(self.chain.iter().map(|x| x.der.clone()))
            .collect()
    }

    pub fn cert_and_intermediates(&self) -> Vec<Certificate> {
        std::iter::once(self.cert.clone())
            .chain(self.chain.clone())
            .collect()
    }

    pub fn full_chain_and_roots(&self) -> Vec<String> {
        self.cert_and_intermediates()
            .into_iter()
            .map(|c| c.as_pem())
            .chain(iter::once(self.roots.iter().map(|c| c.as_pem()).join("\n")))
            .collect()
    }

    pub fn server_config(
        &self,
        trust_domains: Option<&crate::tls::trust_domains::TrustDomainManager>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ServerConfig, Error> {
        let manager = self.peer_bundle_manager(trust_domains)?;
        let client_cert_verifier =
            crate::tls::workload::TrustDomainVerifier::new(manager, crl_manager);
        let mut sc = ServerConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::tls_versions())
            .expect("server config must be valid")
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(
                self.cert_and_intermediates_der(),
                self.private_key.clone_key(),
            )?;
        sc.alpn_protocols = vec![b"h2".into()];
        // Every connection must run current domain/chain verification; tickets and caches must not
        // restore authentication from a removed bundle generation.
        sc.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        sc.send_tls13_tickets = 0;
        Ok(sc)
    }

    pub(crate) fn peer_bundle_manager(
        &self,
        configured: Option<&crate::tls::trust_domains::TrustDomainManager>,
    ) -> Result<crate::tls::trust_domains::TrustDomainManager, rustls::Error> {
        let manager = configured.cloned().unwrap_or_else(|| {
            crate::tls::trust_domains::TrustDomainManager::new(Default::default())
        });
        manager.configure_local(self)?;
        Ok(manager)
    }

    pub fn client_config(
        &self,
        identity: Vec<Identity>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ClientConfig, rustls::Error> {
        self.client_config_with_trust_domains(identity, crl_manager, None)
    }

    pub fn client_config_with_trust_domains(
        &self,
        identity: Vec<Identity>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
        trust_domains: Option<&crate::tls::trust_domains::TrustDomainManager>,
    ) -> Result<ClientConfig, rustls::Error> {
        let verifier = IdentityVerifier {
            manager: self.peer_bundle_manager(trust_domains)?,
            identity,
            crl_manager,
        };
        let mut cc = ClientConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::tls_versions())
            .expect("client config must be valid")
            .dangerous() // Customer verifier is requires "dangerous" opt-in
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(
                self.cert_and_intermediates_der(),
                self.private_key.clone_key(),
            )?;
        cc.alpn_protocols = vec![b"h2".into()];
        cc.resumption = Resumption::disabled();
        cc.enable_sni = false;
        Ok(cc)
    }

    pub fn outbound_connector(
        &self,
        identity: Vec<Identity>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<OutboundConnector, Error> {
        self.outbound_connector_with_trust_domains(identity, crl_manager, None)
    }

    pub fn outbound_connector_with_trust_domains(
        &self,
        identity: Vec<Identity>,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
        trust_domains: Option<&crate::tls::trust_domains::TrustDomainManager>,
    ) -> Result<OutboundConnector, Error> {
        let cc = self.client_config_with_trust_domains(identity, crl_manager, trust_domains)?;
        Ok(OutboundConnector {
            client_config: Arc::new(cc),
        })
    }

    pub(crate) fn register_peer(
        &self,
        manager: Option<&crate::tls::trust_domains::TrustDomainManager>,
        ssl: &CommonState,
        peer: Identity,
        usage: webpki::KeyUsage,
        crls: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<crate::tls::trust_domains::TrustDomainHandle, Error> {
        let manager = self.peer_bundle_manager(manager)?;
        let chain = ssl
            .peer_certificates()
            .ok_or_else(|| {
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })?
            .to_vec();
        let handle = manager.register_with_crls(peer, chain, usage, crls);
        if *handle.subscribe().borrow() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
            .into());
        }
        Ok(handle)
    }

    pub fn dump_chain(&self) -> Bytes {
        self.chain.iter().map(|c| c.as_pem()).join("\n").into()
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.cert.expiry.not_after
    }

    pub fn refresh_at(&self) -> SystemTime {
        let expiry = &self.cert.expiry;
        match expiry.not_after.duration_since(expiry.not_before) {
            Ok(valid_for) => expiry.not_before + valid_for / 2,
            Err(_) => expiry.not_after,
        }
    }

    pub fn get_duration_until_refresh(&self) -> Duration {
        let expiry = &self.cert.expiry;
        let halflife = expiry
            .not_after
            .duration_since(expiry.not_before)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            / 2;
        // If now() is earlier than not_before, we need to refresh ASAP, so return 0.
        let elapsed = SystemTime::now()
            .duration_since(expiry.not_before)
            .unwrap_or(halflife);
        halflife
            .checked_sub(elapsed)
            .unwrap_or_else(|| Duration::from_secs(0))
    }
}

const CERTIFICATE: &str = "CERTIFICATE";

/// Converts DER encoded data to PEM.
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let mut ans = String::from("-----BEGIN ");
    ans.push_str(label);
    ans.push_str("-----\n");
    let b64 = STANDARD.encode(der);
    let line_length = 60;
    for chunk in b64.chars().collect::<Vec<_>>().chunks(line_length) {
        ans.extend(chunk);
        ans.push('\n');
    }
    ans.push_str("-----END ");
    ans.push_str(label);
    ans.push_str("-----\n");
    ans
}

#[cfg(test)]
mod test {
    use crate::identity::Identity;
    use crate::test_helpers::helpers;
    use crate::tls::mock::{
        TEST_ROOT, TEST_ROOT_KEY, TEST_ROOT2, TEST_ROOT2_KEY, TestIdentity, crl_pem_revoking_cert,
        generate_intermediate_ca,
    };
    use crate::tls::{WorkloadCertificate, io_error_is_cert_revoked};

    use std::io::Write;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::SystemTime;
    use tempfile::NamedTempFile;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn multi_root() {
        helpers::initialize_telemetry();
        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();
        // Joined root
        let mut joined = TEST_ROOT.to_vec();
        joined.push(b'\n');
        joined.extend(TEST_ROOT2);

        // Generate key+cert signed by root1
        let (key, cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT_KEY,
        );
        let cert1 =
            WorkloadCertificate::new(key.as_bytes(), cert.as_bytes(), vec![&joined]).unwrap();

        // Generate key+cert signed by root2
        let (key, cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(60),
            None,
            TEST_ROOT2_KEY,
        );
        let cert2 =
            WorkloadCertificate::new(key.as_bytes(), cert.as_bytes(), vec![&joined]).unwrap();

        // Do a simple handshake between them; we should be able to accept the trusted root
        let manager = crate::tls::trust_domains::TrustDomainManager::from_bundle_map(
            &crate::tls::mock::bundle_map(&[("td", vec![TEST_ROOT, TEST_ROOT2])]),
        )
        .unwrap();
        let server = cert1.server_config(Some(&manager), None).unwrap();
        let tls = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tls.accept(stream).await.unwrap();
            let _ = tls.write(b"serv").await.unwrap();
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let client = cert2
            .outbound_connector_with_trust_domains(vec![id], None, Some(&manager))
            .unwrap();
        let mut tls = client.connect(stream).await.unwrap();

        let _ = tls.write(b"hi").await.unwrap();
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"serv");
    }

    /// Outbound client must abort TLS when the peer's leaf cert appears in the loaded CRL (i.e. is revoked).
    #[tokio::test]
    async fn outbound_rejects_revoked_server_cert() {
        helpers::initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();

        // Generate server key+cert signed by root
        let (server_key, server_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let server_wl = WorkloadCertificate::new(
            server_key.as_bytes(),
            server_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // Generate client key+cert signed by root
        let (client_key, client_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let client_wl = WorkloadCertificate::new(
            client_key.as_bytes(),
            client_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // Generate CRL that revokes the server cert
        let crl_pem = crl_pem_revoking_cert(&server_wl.cert.serial_bytes());

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        // Create CRL manager to load the CRL from file path
        let crl_mgr = Arc::new(
            crate::tls::crl::CrlManager::new(
                crl_file.path().to_path_buf(),
                crate::test_helpers::helpers::test_proxy_metrics(),
            )
            .unwrap(),
        );

        // Create TLS server to listen for incoming connections
        let server_tls = TlsAcceptor::from(Arc::new(server_wl.server_config(None, None).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server_tls.accept(stream).await;
        });

        // Create outbound connector to connect to the TLS server
        // we expect the connection to fail because the CRL is enforced and the server cert is revoked
        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl
            .outbound_connector(vec![id.clone()], Some(crl_mgr))
            .unwrap();
        let err = connector
            .connect(stream)
            .await
            .expect_err("connection should fail: server cert is revoked");
        assert!(io_error_is_cert_revoked(&err));
    }

    /// Outbound client must abort TLS when the peer's IA cert appears in the loaded CRL (i.e. is revoked).
    /// Validates that full cert chain is checked, not just the EE cert.
    #[tokio::test]
    async fn outbound_rejects_revoked_intermediate_cert() {
        helpers::initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();

        // Generate IA signed by TEST_ROOT and a leaf signed by the IA
        let (ia_key, ia_cert, ia_serial_bytes) = generate_intermediate_ca(TEST_ROOT_KEY);
        let (server_key, server_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            ia_key.as_bytes(),
        );
        // Generate server workload certificate with the full chain: leaf cert signed by IA, IA cert, TEST_ROOT as trust anchor
        let server_wl = WorkloadCertificate::new(
            server_key.as_bytes(),
            server_cert.as_bytes(),
            vec![ia_cert.as_bytes(), TEST_ROOT],
        )
        .unwrap();

        // Client uses a direct root-signed cert — not revoked by the CRL
        let (client_key, client_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let client_wl = WorkloadCertificate::new(
            client_key.as_bytes(),
            client_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // CRL signed by TEST_ROOT that revokes the IA — not the leaf cert
        let crl_pem = crl_pem_revoking_cert(&ia_serial_bytes);

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let crl_mgr = Arc::new(
            crate::tls::crl::CrlManager::new(
                crl_file.path().to_path_buf(),
                crate::test_helpers::helpers::test_proxy_metrics(),
            )
            .unwrap(),
        );

        let server_tls = TlsAcceptor::from(Arc::new(server_wl.server_config(None, None).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = server_tls.accept(stream).await;
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl
            .outbound_connector(vec![id.clone()], Some(crl_mgr))
            .unwrap();
        let err = connector
            .connect(stream)
            .await
            .expect_err("connection should fail: intermediate cert is revoked");
        assert!(io_error_is_cert_revoked(&err));
    }

    #[test]
    fn mapped_three_independent_roots_both_tls_roles() {
        use crate::tls::mock::{bundle_map, generate_ca_material, generate_workload};
        use crate::tls::trust_domains::TrustDomainManager;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};
        use rustls::server::danger::ClientCertVerifier;
        let domains = ["prod.example", "nonprod.example", "build.example"];
        let cas = domains.map(|_| generate_ca_material("same-subject", 1));
        let pems: Vec<_> = cas
            .iter()
            .map(|c| c.1.self_signed(&c.0).unwrap().pem())
            .collect();
        let entries: Vec<_> = domains
            .iter()
            .zip(&pems)
            .map(|(d, p)| (*d, vec![p.as_bytes()]))
            .collect();
        let manager = TrustDomainManager::from_bundle_map(&bundle_map(&entries)).unwrap();
        let inbound = crate::tls::workload::TrustDomainVerifier::new(manager.clone(), None);
        for (domain_index, domain) in domains.iter().enumerate() {
            for (root_index, ca) in cas.iter().enumerate() {
                let spiffe = format!("spiffe://{domain}/ns/n/sa/a");
                let cert = generate_workload(ca, &spiffe);
                let expected = Identity::from_str(&spiffe).unwrap();
                let outbound = crate::tls::IdentityVerifier {
                    manager: manager.clone(),
                    identity: vec![expected],
                    crl_manager: None,
                };
                let inbound_ok = inbound
                    .verify_client_cert(&cert.cert.der, &[], UnixTime::now())
                    .is_ok();
                let outbound_ok = outbound
                    .verify_server_cert(
                        &cert.cert.der,
                        &[],
                        &ServerName::IpAddress(
                            "127.0.0.1".parse::<std::net::IpAddr>().unwrap().into(),
                        ),
                        &[],
                        UnixTime::now(),
                    )
                    .is_ok();
                assert_eq!(
                    inbound_ok,
                    domain_index == root_index,
                    "inbound {domain} root {root_index}"
                );
                assert_eq!(
                    outbound_ok,
                    domain_index == root_index,
                    "outbound {domain} root {root_index}"
                );
            }
        }
        let shared = TrustDomainManager::from_bundle_map(&bundle_map(&[
            (domains[0], vec![pems[0].as_bytes()]),
            (domains[1], vec![pems[0].as_bytes()]),
        ]))
        .unwrap();
        let inbound = crate::tls::workload::TrustDomainVerifier::new(shared.clone(), None);
        for domain in domains {
            let spiffe = format!("spiffe://{domain}/ns/n/sa/a");
            let cert = generate_workload(&cas[0], &spiffe);
            let outbound = crate::tls::IdentityVerifier {
                manager: shared.clone(),
                identity: vec![Identity::from_str(&spiffe).unwrap()],
                crl_manager: None,
            };
            assert_eq!(
                inbound
                    .verify_client_cert(&cert.cert.der, &[], UnixTime::now())
                    .is_ok(),
                domain != domains[2]
            );
            assert_eq!(
                outbound
                    .verify_server_cert(
                        &cert.cert.der,
                        &[],
                        &ServerName::IpAddress(
                            "127.0.0.1".parse::<std::net::IpAddr>().unwrap().into()
                        ),
                        &[],
                        UnixTime::now()
                    )
                    .is_ok(),
                domain != domains[2]
            );
        }
    }
    #[test]
    fn strict_uri_purpose_time_signature_and_exact_principal() {
        use crate::tls::mock::{bundle_map, generate_ca_material, generate_leaf_material};
        use crate::tls::trust_domains::TrustDomainManager;
        use rcgen::*;
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{ServerName, UnixTime};
        use rustls::server::danger::ClientCertVerifier;
        let ca = generate_ca_material("root", 1);
        let pem = ca.1.self_signed(&ca.0).unwrap().pem();
        let manager =
            TrustDomainManager::from_bundle_map(&bundle_map(&[("td", vec![pem.as_bytes()])]))
                .unwrap();
        let expected = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();
        let inbound = crate::tls::workload::TrustDomainVerifier::new(manager.clone(), None);
        let outbound = crate::tls::IdentityVerifier {
            manager,
            identity: vec![expected],
            crl_manager: None,
        };
        let name = ServerName::IpAddress("127.0.0.1".parse::<std::net::IpAddr>().unwrap().into());
        for (uris, dns, valid) in [
            (vec![], false, false),
            (vec![], true, false),
            (vec!["spiffe://td/ns/n/sa/a"], true, true),
            (
                vec!["spiffe://td/ns/n/sa/a", "spiffe://td/ns/n/sa/a"],
                false,
                false,
            ),
            (
                vec!["spiffe://td/ns/n/sa/a", "spiffe://other/ns/n/sa/b"],
                false,
                false,
            ),
            (vec!["spiffe://td/ns/n/sa/a", "not-spiffe"], false, false),
            (vec!["spiffe://td"], false, false),
            (vec!["spiffe://td/"], false, false),
            (vec!["spiffe://TD/ns/n/sa/a"], false, false),
            (vec!["spiffe://td:443/ns/n/sa/a"], false, false),
            (vec!["spiffe://user@td/ns/n/sa/a"], false, false),
            (vec!["spiffe://td/ns//sa/a"], false, false),
            (vec!["spiffe://td/ns/../sa/a"], false, false),
            (vec!["spiffe://td/ns/n/sa/a?x"], false, false),
            (vec!["spiffe://td/ns/n/sa/a#x"], false, false),
            (vec!["spiffe://td/ns/n/sa/%61"], false, false),
            (vec!["spiffe://td/ns/n/sa/a\0"], false, false),
        ] {
            let leaf = generate_leaf_material("spiffe://td/ns/n/sa/a", 100);
            let mut p = leaf.1;
            p.subject_alt_names = uris
                .iter()
                .map(|u| SanType::URI(string::Ia5String::try_from((*u).to_string()).unwrap()))
                .collect();
            if dns {
                p.subject_alt_names
                    .push(SanType::DnsName("ordinary.example".try_into().unwrap()));
            }
            let cert = p
                .signed_by(&leaf.0, &Issuer::from_params(&ca.1, &ca.0))
                .unwrap();
            assert_eq!(
                inbound
                    .verify_client_cert(cert.der(), &[], UnixTime::now())
                    .is_ok(),
                valid,
                "inbound {uris:?}"
            );
            assert_eq!(
                outbound
                    .verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now())
                    .is_ok(),
                valid,
                "outbound {uris:?}"
            );
        }
        for (client, server) in [(true, false), (false, true)] {
            let leaf = generate_leaf_material("spiffe://td/ns/n/sa/a", 100);
            let mut p = leaf.1;
            p.extended_key_usages = vec![if client {
                ExtendedKeyUsagePurpose::ClientAuth
            } else {
                ExtendedKeyUsagePurpose::ServerAuth
            }];
            let cert = p
                .signed_by(&leaf.0, &Issuer::from_params(&ca.1, &ca.0))
                .unwrap();
            assert_eq!(
                inbound
                    .verify_client_cert(cert.der(), &[], UnixTime::now())
                    .is_ok(),
                client
            );
            assert_eq!(
                outbound
                    .verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now())
                    .is_ok(),
                server
            );
        }
        for negative in [
            "expired",
            "future",
            "ca-leaf",
            "bad-signature",
            "wrong-principal",
        ] {
            let leaf = generate_leaf_material("spiffe://td/ns/n/sa/a", 100);
            let mut p = leaf.1;
            match negative {
                "expired" => {
                    p.not_before = (SystemTime::now() - Duration::from_secs(120)).into();
                    p.not_after = (SystemTime::now() - Duration::from_secs(60)).into();
                }
                "future" => p.not_before = (SystemTime::now() + Duration::from_secs(60)).into(),
                "ca-leaf" => {
                    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                    p.key_usages.push(KeyUsagePurpose::KeyCertSign);
                }
                "wrong-principal" => {
                    p.subject_alt_names = vec![SanType::URI(
                        "spiffe://td/ns/n/sa/wrong".try_into().unwrap(),
                    )]
                }
                _ => {}
            }
            let cert = p
                .signed_by(&leaf.0, &Issuer::from_params(&ca.1, &ca.0))
                .unwrap();
            let mut der = cert.der().to_vec();
            if negative == "bad-signature" {
                *der.last_mut().unwrap() ^= 1;
            }
            let der = rustls::pki_types::CertificateDer::from(der);
            assert_eq!(
                inbound
                    .verify_client_cert(&der, &[], UnixTime::now())
                    .is_ok(),
                negative == "wrong-principal",
                "inbound {negative}"
            );
            assert!(
                outbound
                    .verify_server_cert(&der, &[], &name, &[], UnixTime::now())
                    .is_err(),
                "outbound {negative}"
            );
        }
    }

    #[tokio::test]
    async fn mapped_live_tls_and_server_resumption_cannot_restore_removed_roots() {
        use crate::tls::mock::{bundle_map, generate_ca_material, generate_workload};
        use crate::tls::trust_domains::TrustDomainManager;
        let ca = generate_ca_material("root", 1);
        let pem = ca.1.self_signed(&ca.0).unwrap().pem();
        let mut map = NamedTempFile::new().unwrap();
        map.write_all(&bundle_map(&[
            ("server", vec![pem.as_bytes()]),
            ("client", vec![pem.as_bytes()]),
        ]))
        .unwrap();
        let manager = TrustDomainManager::new(map.path().to_path_buf());
        let server = generate_workload(&ca, "spiffe://server/ns/n/sa/server");
        let client = generate_workload(&ca, "spiffe://client/ns/n/sa/client");
        let sc = Arc::new(server.server_config(Some(&manager), None).unwrap());
        assert_eq!(sc.send_tls13_tickets, 0);
        assert!(!sc.session_storage.can_cache());
        let mut cc = client
            .client_config_with_trust_domains(
                vec![server.identity().unwrap()],
                None,
                Some(&manager),
            )
            .unwrap();
        cc.resumption = rustls::client::Resumption::in_memory_sessions(128);
        let connector = crate::tls::OutboundConnector {
            client_config: Arc::new(cc),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        for round in 0..3 {
            if round == 2 {
                map.as_file_mut().set_len(0).unwrap();
                use std::io::{Seek, SeekFrom};
                map.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
                map.write_all(&bundle_map(&[])).unwrap();
                manager.reload().unwrap();
            }
            let acceptor = TlsAcceptor::from(sc.clone());
            let (done_tx, done_rx) = tokio::sync::oneshot::channel();
            let (tcp_client, tcp_server) =
                tokio::join!(TcpStream::connect(addr), listener.accept());
            let accepted = tokio::spawn(async move {
                match acceptor.accept(tcp_server.unwrap().0).await {
                    Ok(mut tls) => {
                        let kind = tls.get_ref().1.handshake_kind();
                        let _ = tls.write_all(b"x").await;
                        let _ = done_tx.send(kind);
                        true
                    }
                    Err(_) => false,
                }
            });
            let tls = connector.clone().connect(tcp_client.unwrap()).await;
            if round < 2 {
                let mut tls = tls.unwrap();
                let mut byte = [0];
                tls.read_exact(&mut byte).await.unwrap();
                assert_eq!(
                    tls.get_ref().1.handshake_kind(),
                    Some(rustls::HandshakeKind::Full)
                );
                assert_eq!(done_rx.await.unwrap(), Some(rustls::HandshakeKind::Full));
                assert!(accepted.await.unwrap());
            } else {
                assert!(tls.is_err());
                assert!(!accepted.await.unwrap());
            }
        }
    }
}
