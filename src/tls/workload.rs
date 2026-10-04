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
use std::error::Error;
use std::fmt::{Debug, Display};

use crate::tls::lib::provider;
use crate::tls::{ServerCertProvider, TlsError};
use futures_util::TryFutureExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertRevocationListError, ClientConfig, DigitallySignedStruct, DistinguishedName, OtherError,
    SignatureScheme,
};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use webpki::{CertRevocationList, KeyUsage};

use crate::tls;
use tokio::net::TcpStream;
use tokio_rustls::client;
use tracing::trace;

#[derive(Clone, Debug)]
pub struct InboundAcceptor<F: ServerCertProvider> {
    provider: F,
}

impl<F: ServerCertProvider> InboundAcceptor<F> {
    pub fn new(provider: F) -> Self {
        Self { provider }
    }
}

#[derive(Debug)]
pub(super) struct TrustDomainVerifier {
    manager: tls::trust_domains::TrustDomainManager,
    crl_manager: Option<Arc<tls::crl::CrlManager>>,
}

impl TrustDomainVerifier {
    pub fn new(
        manager: tls::trust_domains::TrustDomainManager,
        crl_manager: Option<Arc<tls::crl::CrlManager>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            manager,
            crl_manager,
        })
    }
}

fn peer_identity(cert: &CertificateDer<'_>) -> Result<Identity, rustls::Error> {
    let (remaining, cert) = x509_parser::parse_x509_certificate(cert)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    if !remaining.is_empty() {
        return Err(rustls::CertificateError::BadEncoding.into());
    }
    tls::certificate::identities(&cert)
        .map_err(|_| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?
        .into_iter()
        .next()
        .ok_or_else(|| rustls::CertificateError::ApplicationVerificationFailure.into())
}

impl ClientCertVerifier for TrustDomainVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let peer = peer_identity(end_entity)?;
        let (generation, roots) = self.manager.selected(&peer)?;
        let crls = self
            .crl_manager
            .as_deref()
            .map(|m| m.get_crls())
            .unwrap_or_default();
        tls::revocation::verify_cert_chain(
            end_entity,
            intermediates,
            &roots,
            now,
            KeyUsage::client_auth(),
            &crls,
        )
        .map_err(webpki_error_to_rustls)?;
        self.manager.check_generation(generation)?;
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl<F> tls_listener::AsyncTls<TcpStream> for InboundAcceptor<F>
where
    F: ServerCertProvider + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<TcpStream>;
    type Error = TlsError;
    type AcceptFuture = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn accept(&self, conn: TcpStream) -> Self::AcceptFuture {
        let mut acceptor = self.provider.clone();
        Box::pin(async move {
            let tls = acceptor.fetch_cert().await?;
            tokio_rustls::TlsAcceptor::from(tls)
                .accept(conn)
                .map_err(TlsError::Handshake)
                .await
        })
    }
}

#[derive(Clone, Debug)]
pub struct OutboundConnector {
    pub(super) client_config: Arc<ClientConfig>,
}

impl OutboundConnector {
    pub async fn connect<IO>(self, stream: IO) -> Result<client::TlsStream<IO>, io::Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let c = tokio_rustls::TlsConnector::from(self.client_config);
        // Use dummy value for domain because it doesn't matter.
        c.connect(
            ServerName::IpAddress(std::net::Ipv4Addr::new(0, 0, 0, 0).into()),
            stream,
        )
        .await
    }
}

#[derive(Debug)]
pub struct IdentityVerifier {
    pub(super) manager: tls::trust_domains::TrustDomainManager,
    pub(super) identity: Vec<Identity>,
    pub(super) crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
}

/// Maps `rustls-webpki` errors to `rustls::Error`.
///
/// We map the variants that carry structured `CertificateError` / CRL types used by rustls for
/// handshake reporting; everything else (signature-algorithm context, uncommon path failures, and
/// future `#[non_exhaustive]` variants) is wrapped in [`CertificateError::Other`] while preserving
/// the original `webpki::Error` for logs.
fn webpki_error_to_rustls(error: webpki::Error) -> rustls::Error {
    use rustls::CertificateError;
    use webpki::Error;

    match error {
        Error::BadDer | Error::BadDerTime | Error::TrailingData(_) => {
            CertificateError::BadEncoding.into()
        }
        Error::CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        Error::CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        Error::UnknownIssuer => CertificateError::UnknownIssuer.into(),
        Error::CertNotValidForName(ctx) => CertificateError::NotValidForNameContext {
            expected: ctx.expected,
            presented: ctx.presented,
        }
        .into(),
        Error::CertRevoked => CertificateError::Revoked.into(),
        Error::UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        Error::CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        Error::IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),
        Error::InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        Error::RequiredEkuNotFound | Error::RequiredEkuNotFoundContext(_) => {
            CertificateError::InvalidPurpose.into()
        }
        e => CertificateError::Other(OtherError(std::sync::Arc::new(e))).into(),
    }
}

/// DebugAsDisplay is a shim to make an object implement Debug with its Display format
/// This is to workaround rustls only using Debug which makes our errors worse.
struct DebugAsDisplay<T>(T);

impl<T: Display> Debug for DebugAsDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}
impl<T: Display> Display for DebugAsDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<T: Error + Display> Error for DebugAsDisplay<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

// Rustls doesn't natively validate URI SAN.
// Build our own verifier, inspired by https://github.com/rustls/rustls/blob/ccb79947a4811412ee7dcddcd0f51ea56bccf101/rustls/src/webpki/server_verifier.rs#L239.
impl ServerCertVerifier for IdentityVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a trusted `RootCertStore` CA
    /// - Not expired
    /// - Optional CRL checking (same webpki policy as inbound `WebPkiClientVerifier` when enabled)
    /// - SPIFFE URI SAN matches expected identities (not DNS `ServerName`)
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _sn: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let crls: Arc<Vec<CertRevocationList<'static>>> = self
            .crl_manager
            .as_deref()
            .map(|mgr| mgr.get_crls())
            .unwrap_or_default();

        let peer = peer_identity(end_entity)?;
        let (generation, roots) = self.manager.selected(&peer)?;
        // The peer domain selects the store before native chain and purpose verification.
        crate::tls::revocation::verify_cert_chain(
            end_entity,
            intermediates,
            &roots,
            now,
            KeyUsage::server_auth(),
            &crls,
        )
        .map_err(webpki_error_to_rustls)?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {ocsp_response:?}");
        }

        if !self.identity.contains(&peer) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(DebugAsDisplay(
                    TlsError::SanError(self.identity.clone(), vec![peer]),
                )))),
            ));
        }
        self.manager.check_generation(generation)?;

        Ok(ServerCertVerified::assertion())
    }

    // Rest use the default implementations

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
