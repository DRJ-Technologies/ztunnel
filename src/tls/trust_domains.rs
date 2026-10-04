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
use crate::strng::Strng;
use crate::tls::{WorkloadCertificate, revocation::verify_cert_chain};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use notify::{Config, RecommendedWatcher};
use notify_debouncer_full::{
    DebounceEventResult, Debouncer, FileIdMap, new_debouncer_opt, notify::RecursiveMode,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, warn};
use webpki::KeyUsage;

#[derive(Debug, thiserror::Error)]
pub enum TrustDomainsError {
    #[error("failed to read SPIFFE bundle map: {0}")]
    IoError(#[from] std::io::Error),
    #[error("invalid SPIFFE bundle map: {0}")]
    Invalid(String),
    #[error("failed to watch SPIFFE bundle map: {0}")]
    WatchError(String),
}

/// One complete projection; generations are process-local registration custody, never wire fields.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    generation: u64,
    authoritative: bool,
    failed: bool,
    stores: HashMap<Strng, Arc<RootCertStore>>,
}

#[derive(Clone)]
pub struct TrustDomainManager {
    inner: Arc<Inner>,
}
impl std::fmt::Debug for TrustDomainManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustDomainManager")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}
struct Inner {
    path: PathBuf,
    snapshot: RwLock<Snapshot>,
    // Reload and final registration share this lock, preventing missed removal.
    conns: Mutex<Conns>,
    // FileIdMap is required for Kubernetes ..data atomic symlink replacement.
    debouncer: Mutex<Option<Debouncer<RecommendedWatcher, FileIdMap>>>,
}
#[derive(Default)]
struct Conns {
    next_id: u64,
    entries: HashMap<u64, Tracked>,
}
struct Tracked {
    peer: Identity,
    chain: Vec<CertificateDer<'static>>,
    usage: KeyUsage,
    established: UnixTime,
    roots: PeerRoots,
    tx: watch::Sender<bool>,
}

/// Shared with native CRL registration: updates retain the current selected peer-domain roots.
#[derive(Clone, Debug)]
pub struct PeerRoots(Arc<RwLock<Arc<RootCertStore>>>);
impl PeerRoots {
    pub fn new(roots: Arc<RootCertStore>) -> Self {
        Self(Arc::new(RwLock::new(roots)))
    }
    pub fn current(&self) -> Arc<RootCertStore> {
        self.0.read().unwrap().clone()
    }
    fn replace(&self, roots: Arc<RootCertStore>) {
        *self.0.write().unwrap() = roots;
    }
}

impl TrustDomainManager {
    pub fn new(path: PathBuf) -> Self {
        let manager = Self {
            inner: Arc::new(Inner {
                path,
                snapshot: RwLock::new(Snapshot::default()),
                conns: Mutex::new(Conns::default()),
                debouncer: Mutex::new(None),
            }),
        };
        if !manager.inner.path.as_os_str().is_empty() {
            if let Err(e) = manager.reload() {
                debug!(error=%e, "bundle map not yet available");
            }
        }
        manager
    }

    #[cfg(test)]
    pub(crate) fn from_bundle_map(bytes: &[u8]) -> Result<Self, TrustDomainsError> {
        let manager = Self::new(PathBuf::new());
        manager.set(parse(bytes)?, false);
        Ok(manager)
    }

    /// Initial local-only binding. Qualify each delivered candidate independently against our own
    /// SVID, so unrelated certificates in the CA response cannot become local or foreign authority.
    /// Authoritative empty/error states never take this path back to fallback.
    pub fn configure_local(&self, own: &WorkloadCertificate) -> Result<(), rustls::Error> {
        if self.inner.snapshot.read().unwrap().authoritative {
            return Ok(());
        }
        let peer = own.identity().ok_or_else(rejected)?;
        let chain = own.cert_and_intermediates_der();
        let mut qualified = RootCertStore::empty();
        for root in &own.roots {
            let mut candidate = RootCertStore::empty();
            candidate.add(root.der.clone()).map_err(|_| rejected())?;
            if verify_cert_chain(
                &chain[0],
                &chain[1..],
                &candidate,
                UnixTime::now(),
                KeyUsage::client_auth(),
                &[],
            )
            .is_ok()
                && verify_cert_chain(
                    &chain[0],
                    &chain[1..],
                    &candidate,
                    UnixTime::now(),
                    KeyUsage::server_auth(),
                    &[],
                )
                .is_ok()
            {
                qualified.add(root.der.clone()).map_err(|_| rejected())?;
            }
        }
        if qualified.is_empty() {
            return Err(rejected());
        }
        let mut conns = self.inner.conns.lock().unwrap();
        let mut snapshot = self.inner.snapshot.write().unwrap();
        if !snapshot.authoritative
            && !snapshot.failed
            && snapshot
                .stores
                .get(&peer.trust_domain())
                .is_none_or(|r| r.roots != qualified.roots)
        {
            snapshot.generation += 1;
            snapshot
                .stores
                .insert(peer.trust_domain(), Arc::new(qualified));
            revalidate(&mut conns, &snapshot);
        }
        Ok(())
    }

    pub fn disable(&self) {
        self.set(HashMap::new(), true);
    }
    pub fn generation(&self) -> u64 {
        self.inner.snapshot.read().unwrap().generation
    }
    pub fn selected(&self, peer: &Identity) -> Result<(u64, Arc<RootCertStore>), rustls::Error> {
        let snapshot = self.inner.snapshot.read().unwrap();
        if snapshot.failed {
            return Err(rejected());
        }
        let roots = snapshot
            .stores
            .get(&peer.trust_domain())
            .filter(|r| !r.is_empty())
            .ok_or_else(rejected)?;
        Ok((snapshot.generation, roots.clone()))
    }
    pub fn check_generation(&self, generation: u64) -> Result<(), rustls::Error> {
        if self.generation() != generation {
            Err(rejected())
        } else {
            Ok(())
        }
    }
    pub fn reload(&self) -> Result<(), TrustDomainsError> {
        let next = std::fs::read(&self.inner.path)
            .map_err(TrustDomainsError::from)
            .and_then(|s| parse(&s));
        match next {
            Ok(stores) => {
                self.set(stores, false);
                Ok(())
            }
            Err(e) => {
                // Initial optional absence is qualified local-only. Malformed/persistently unreadable
                // input fails closed; any missing update after mapped mode does too.
                let initial_absence = matches!(&e, TrustDomainsError::IoError(e) if e.kind()==std::io::ErrorKind::NotFound)
                    && !self.inner.snapshot.read().unwrap().authoritative;
                if !initial_absence {
                    self.set(HashMap::new(), true);
                }
                Err(e)
            }
        }
    }
    fn set(&self, stores: HashMap<Strng, Arc<RootCertStore>>, failed: bool) {
        let mut conns = self.inner.conns.lock().unwrap();
        let mut snapshot = self.inner.snapshot.write().unwrap();
        snapshot.generation += 1;
        snapshot.authoritative = true;
        snapshot.failed = failed;
        snapshot.stores = stores;
        revalidate(&mut conns, &snapshot);
    }

    /// Always reverify the presented chain against the current selected store under the update lock.
    /// This is stronger than relying on a handshake generation alone and closes the registration gap.
    pub fn register(
        &self,
        peer: Identity,
        chain: Vec<CertificateDer<'static>>,
        usage: KeyUsage,
    ) -> TrustDomainHandle {
        let (tx, rx) = watch::channel(false);
        let mut conns = self.inner.conns.lock().unwrap();
        let selected = self.selected(&peer);
        let now = UnixTime::now();
        let roots = PeerRoots::new(
            selected
                .as_ref()
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|_| Arc::new(RootCertStore::empty())),
        );
        if selected.is_err() || verify_chain(&chain, &roots.current(), usage, now).is_err() {
            let _ = tx.send(true);
            return TrustDomainHandle {
                rx,
                roots,
                trust_domain: peer.trust_domain(),
                _guard: None,
            };
        }
        let id = conns.next_id;
        conns.next_id += 1;
        let trust_domain = peer.trust_domain();
        conns.entries.insert(
            id,
            Tracked {
                peer,
                chain,
                usage,
                established: now,
                roots: roots.clone(),
                tx,
            },
        );
        TrustDomainHandle {
            rx,
            roots,
            trust_domain,
            _guard: Some(Guard {
                inner: Arc::downgrade(&self.inner),
                id,
            }),
        }
    }
    /// Starts watching the file for changes. The parent directory is watched, so ConfigMap updates
    /// (an atomic swap of the `..data` symlink) and the file appearing later are both picked up.
    pub fn start_file_watcher(&self) -> Result<(), TrustDomainsError> {
        let watch_path = self.inner.path.parent().ok_or_else(|| {
            TrustDomainsError::WatchError("SPIFFE bundles path has no parent directory".to_string())
        })?;
        let inner = Arc::downgrade(&self.inner);
        let mut debouncer = new_debouncer_opt(
            Duration::from_secs(2),
            None,
            move |result: DebounceEventResult| {
                let Some(inner) = inner.upgrade() else { return; };
                let manager = TrustDomainManager { inner };
                match result {
                Ok(events) if !events.is_empty() => {
                    debug!("SPIFFE bundles directory changed, reloading");
                    if let Err(e) = manager.reload() {
                        warn!(error = %e, "failed to reload SPIFFE bundles, mapped authority disabled");
                    }
                }
                Ok(_) => {}
                Err(errors) => {
                    manager.disable();
                    for error in errors {
                        debug!(error = ?error, "SPIFFE bundles watcher error");
                    }
                }
                }
            },
            FileIdMap::new(),
            Config::default(),
        )
        .map_err(|e| TrustDomainsError::WatchError(e.to_string()))?;
        debouncer
            .watch(watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| TrustDomainsError::WatchError(e.to_string()))?;
        *self.inner.debouncer.lock().unwrap() = Some(debouncer);
        Ok(())
    }
}
fn revalidate(conns: &mut Conns, snapshot: &Snapshot) {
    conns.entries.retain(|_, c| {
        let roots = snapshot.stores.get(&c.peer.trust_domain());
        let valid = !snapshot.failed
            && roots.is_some_and(|r| verify_chain(&c.chain, r, c.usage, c.established).is_ok());
        if valid {
            c.roots.replace(roots.unwrap().clone());
        } else {
            c.roots.replace(Arc::new(RootCertStore::empty()));
            let _ = c.tx.send(true);
        }
        valid
    });
}

fn rejected() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}
fn verify_chain(
    chain: &[CertificateDer<'static>],
    roots: &RootCertStore,
    usage: KeyUsage,
    now: UnixTime,
) -> Result<(), rustls::Error> {
    let Some((leaf, intermediates)) = chain.split_first() else {
        return Err(rejected());
    };
    verify_cert_chain(leaf, intermediates, roots, now, usage, &[])
        .map(|_| ())
        .map_err(|_| rejected())
}

pub struct TrustDomainHandle {
    rx: watch::Receiver<bool>,
    pub roots: PeerRoots,
    trust_domain: Strng,
    _guard: Option<Guard>,
}
impl TrustDomainHandle {
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }
    pub fn trust_domain(&self) -> &Strng {
        &self.trust_domain
    }
    pub async fn removed(&mut self) {
        loop {
            if *self.rx.borrow_and_update() {
                return;
            }
            if self.rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}
pub async fn wait_for_removal(handle: Option<&mut TrustDomainHandle>) {
    match handle {
        None => std::future::pending().await,
        Some(h) => h.removed().await,
    }
}
struct Guard {
    inner: Weak<Inner>,
    id: u64,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            inner.conns.lock().unwrap().entries.remove(&self.id);
        }
    }
}

// Native serde Visitor preserves decoded member uniqueness recursively before any security consumer.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON with unique object members")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Unique, M::Error> {
                let mut v = serde_json::Map::new();
                while let Some(k) = m.next_key::<String>()? {
                    if v.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate decoded JSON member"));
                    }
                    v.insert(k, m.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(v)))
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut s: S) -> Result<Unique, S::Error> {
                let mut v = Vec::new();
                while let Some(x) = s.next_element::<Unique>()? {
                    v.push(x.0)
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(V)
    }
}
fn parse(content: &[u8]) -> Result<HashMap<Strng, Arc<RootCertStore>>, TrustDomainsError> {
    let invalid = |m: &str| TrustDomainsError::Invalid(m.into());
    let value = serde_json::from_slice::<Unique>(content)
        .map_err(|e| invalid(&e.to_string()))?
        .0;
    let domains = value
        .get("trust_domains")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("missing trust_domains object"))?;
    let mut stores = HashMap::new();
    for (domain, bundle) in domains {
        if !crate::identity::manager::valid_trust_domain(domain) {
            return Err(invalid("noncanonical trust domain"));
        }
        let keys = bundle
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("missing keys array"))?;
        let mut roots = RootCertStore::empty();
        for key in keys {
            if !key.is_object() {
                return Err(invalid("JWK must be an object"));
            }
            let kty = key.get("kty").and_then(Value::as_str);
            if key.get("use").and_then(Value::as_str) != Some("x509-svid")
                || !matches!(kty, Some("RSA" | "EC"))
            {
                continue;
            }
            let x5c = key
                .get("x5c")
                .and_then(Value::as_array)
                .filter(|v| v.len() == 1)
                .ok_or_else(|| invalid("X509-SVID requires one CA"))?;
            let der = STANDARD
                .decode(x5c[0].as_str().ok_or_else(|| invalid("invalid x5c"))?)
                .map_err(|_| invalid("invalid base64 CA"))?;
            let (remaining, cert) = x509_parser::parse_x509_certificate(&der)
                .map_err(|_| invalid("invalid CA certificate"))?;
            if !remaining.is_empty() || !cert.is_ca() {
                return Err(invalid("not a CA certificate"));
            }
            if key.get("kid").is_some() {
                return Err(invalid("X509-SVID kid is forbidden"));
            }
            let field = |name: &str| -> Result<Vec<u8>, TrustDomainsError> {
                URL_SAFE_NO_PAD
                    .decode(
                        key.get(name)
                            .and_then(Value::as_str)
                            .ok_or_else(|| invalid("missing public key field"))?,
                    )
                    .map_err(|_| invalid("invalid public key field"))
            };
            match (
                kty,
                cert.public_key()
                    .parsed()
                    .map_err(|_| invalid("invalid public key"))?,
            ) {
                (Some("RSA"), x509_parser::public_key::PublicKey::RSA(rsa)) => {
                    if field("n")? != rsa.modulus.strip_prefix(&[0]).unwrap_or(rsa.modulus)
                        || field("e")? != rsa.exponent.strip_prefix(&[0]).unwrap_or(rsa.exponent)
                    {
                        return Err(invalid("JWK does not match CA key"));
                    }
                }
                (Some("EC"), x509_parser::public_key::PublicKey::EC(ec)) => {
                    let curve = cert
                        .public_key()
                        .algorithm
                        .parameters
                        .as_ref()
                        .and_then(|p| p.as_oid().ok())
                        .map(|o| o.to_id_string());
                    let expected = match curve.as_deref() {
                        Some("1.2.840.10045.3.1.7") => "P-256",
                        Some("1.3.132.0.34") => "P-384",
                        Some("1.3.132.0.35") => "P-521",
                        _ => return Err(invalid("unsupported EC curve")),
                    };
                    if key.get("crv").and_then(Value::as_str) != Some(expected) {
                        return Err(invalid("EC curve mismatch"));
                    }
                    let x = field("x")?;
                    let y = field("y")?;
                    let point = ec.data();
                    let length = match expected {
                        "P-256" => 32,
                        "P-384" => 48,
                        _ => 66,
                    };
                    if x.len() != length
                        || y.len() != length
                        || point.first() != Some(&4)
                        || point[1..] != [x, y].concat()
                    {
                        return Err(invalid("EC JWK does not match CA key"));
                    }
                }
                _ => return Err(invalid("JWK key type mismatch")),
            }
            roots
                .add(CertificateDer::from(der))
                .map_err(|_| invalid("invalid trust anchor"))?;
        }
        stores.insert(Strng::from(domain.as_str()), Arc::new(roots));
    }
    Ok(stores)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::mock::{bundle_map, generate_ca_material, generate_workload};
    use std::io::Write;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    fn write(file: &mut NamedTempFile, bytes: &[u8]) {
        use std::io::{Seek, SeekFrom};
        file.as_file_mut().set_len(0).unwrap();
        file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
    }

    #[test]
    fn decoded_duplicates_every_object_and_invalid_ca_are_atomic() {
        for document in [
            r#"{"trust_domains":{},"trust_domains":{}}"#,
            r#"{"trust_domains":{"a":{},"\u0061":{}}}"#,
            r#"{"trust_domains":{"a":{"keys":[],"k\u0065ys":[]}}}"#,
            r#"{"trust_domains":{"a":{"keys":[{"kty":"EC","\u006bty":"RSA"}]}}}"#,
            r#"{"trust_domains":{},"metadata":{"a":1,"a":2}}"#,
            r#"{"trust_domains":{"*":{"keys":[]}}}"#,
            r#"{"trust_domains":{"A":{"keys":[]}}}"#,
            r#"{"trust_domains":{"a:443":{"keys":[]}}}"#,
            r#"{"trust_domains":{"":{"keys":[]}}}"#,
        ] {
            assert!(parse(document.as_bytes()).is_err(), "{document}");
        }
        let ca = generate_ca_material("root", 1);
        let pem = ca.1.self_signed(&ca.0).unwrap().pem();
        let mut value: Value = serde_json::from_slice(&bundle_map(&[
            ("a", vec![pem.as_bytes()]),
            ("b", vec![pem.as_bytes()]),
        ]))
        .unwrap();
        let key = &mut value["trust_domains"]["b"]["keys"][0];
        key["x5c"] = serde_json::json!(["invalid"]);
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value: Value =
            serde_json::from_slice(&bundle_map(&[("a", vec![pem.as_bytes()])])).unwrap();
        let key = &mut value["trust_domains"]["a"]["keys"][0];
        // Matching concatenated point bytes cannot excuse noncanonical coordinate widths.
        let y = key["y"].as_str().unwrap().to_owned();
        let x = key["x"].as_str().unwrap().to_owned();
        key["x"] = URL_SAFE_NO_PAD
            .encode(
                [
                    URL_SAFE_NO_PAD.decode(x).unwrap(),
                    URL_SAFE_NO_PAD.decode(y).unwrap(),
                ]
                .concat(),
            )
            .into();
        key["y"] = "".into();
        assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let unknown=br#"{"trust_domains":{"a":{"keys":[{"kty":"oct","use":"x509-svid"},{"kty":"EC","use":"sig"}]}}}"#;
        assert!(parse(unknown).unwrap()[&Strng::from("a")].is_empty());
    }

    #[test]
    fn startup_qualifies_only_own_svid_anchors_and_mapped_empty_never_falls_back() {
        let local = generate_ca_material("same-name", 1);
        let foreign = generate_ca_material("same-name", 1);
        let own = generate_workload(&local, "spiffe://local/ns/n/sa/me");
        // Use the native certificate representation to append an unrelated delivered root.
        let mut own = own;
        own.roots.push(
            generate_workload(&foreign, "spiffe://foreign/ns/n/sa/f")
                .roots
                .remove(0),
        );

        let tmp = tempfile::tempdir().unwrap();
        let manager = TrustDomainManager::new(tmp.path().join("absent.json"));
        manager.configure_local(&own).unwrap();
        let id = own.identity().unwrap();
        let (_, roots) = manager.selected(&id).unwrap();
        assert_eq!(roots.len(), 1);
        let bad_local = generate_workload(&foreign, "spiffe://local/ns/n/sa/attacker");
        assert!(
            verify_chain(
                &bad_local.cert_and_intermediates_der(),
                &roots,
                KeyUsage::client_auth(),
                UnixTime::now()
            )
            .is_err()
        );
        let foreign_id = Identity::from_str("spiffe://foreign/ns/n/sa/attacker").unwrap();
        assert!(manager.selected(&foreign_id).is_err());
        assert!(manager.reload().is_err()); // repeated initial absence remains qualified local-only
        assert!(manager.selected(&id).is_ok());
        manager.set(HashMap::new(), false);
        manager.configure_local(&own).unwrap();
        assert!(manager.selected(&id).is_err());
        assert!(manager.reload().is_err()); // now deletion is an authoritative error
        manager.configure_local(&own).unwrap();
        assert!(manager.selected(&id).is_err());
    }

    #[tokio::test]
    async fn rotation_removal_local_empty_error_recovery_and_selected_crl_roots() {
        let old = generate_ca_material("same-name", 1);
        let new = generate_ca_material("same-name", 1);
        let b = generate_ca_material("same-name", 1);
        let old_pem = old.1.self_signed(&old.0).unwrap().pem();
        let new_pem = new.1.self_signed(&new.0).unwrap().pem();
        let b_pem = b.1.self_signed(&b.0).unwrap().pem();
        let old_cert = generate_workload(&old, "spiffe://a/ns/n/sa/old");
        let new_cert = generate_workload(&new, "spiffe://a/ns/n/sa/new");
        let b_cert = generate_workload(&b, "spiffe://b/ns/n/sa/b");
        let mut file = NamedTempFile::new().unwrap();
        write(
            &mut file,
            &bundle_map(&[
                ("a", vec![old_pem.as_bytes(), new_pem.as_bytes()]),
                ("b", vec![b_pem.as_bytes()]),
            ]),
        );
        let manager = TrustDomainManager::new(file.path().to_path_buf());
        manager.configure_local(&old_cert).unwrap();
        let mut old_handle = manager.register(
            old_cert.identity().unwrap(),
            old_cert.cert_and_intermediates_der(),
            KeyUsage::client_auth(),
        );
        let new_handle = manager.register(
            new_cert.identity().unwrap(),
            new_cert.cert_and_intermediates_der(),
            KeyUsage::server_auth(),
        );
        let b_handle = manager.register(
            b_cert.identity().unwrap(),
            b_cert.cert_and_intermediates_der(),
            KeyUsage::client_auth(),
        );
        assert_eq!(manager.inner.conns.lock().unwrap().entries.len(), 3);
        let selected = new_handle.roots.clone();
        write(
            &mut file,
            &bundle_map(&[
                ("a", vec![new_pem.as_bytes()]),
                ("b", vec![b_pem.as_bytes()]),
            ]),
        );
        manager.reload().unwrap();
        tokio::time::timeout(Duration::from_secs(1), old_handle.removed())
            .await
            .unwrap();
        assert!(!*new_handle.subscribe().borrow());
        assert!(!*b_handle.subscribe().borrow());
        assert_eq!(selected.current().len(), 1);
        assert!(
            verify_chain(
                &old_cert.cert_and_intermediates_der(),
                &selected.current(),
                KeyUsage::client_auth(),
                UnixTime::now()
            )
            .is_err()
        );
        // The manager tracks local peers too: no own-domain exemption.
        write(
            &mut file,
            &bundle_map(&[("a", vec![]), ("b", vec![b_pem.as_bytes()])]),
        );
        manager.reload().unwrap();
        assert!(*new_handle.subscribe().borrow());
        assert!(!*b_handle.subscribe().borrow());
        write(
            &mut file,
            br#"{"trust_domains":{"b":{"keys":[],"keys":[]}}}"#,
        );
        assert!(manager.reload().is_err());
        assert!(*b_handle.subscribe().borrow());
        assert_eq!(manager.inner.conns.lock().unwrap().entries.len(), 0);
        assert!(manager.selected(&b_cert.identity().unwrap()).is_err());
        write(&mut file, &bundle_map(&[("b", vec![b_pem.as_bytes()])]));
        manager.reload().unwrap();
        assert!(manager.selected(&b_cert.identity().unwrap()).is_ok());
        drop(file);
        assert!(manager.reload().is_err());
        assert!(manager.selected(&b_cert.identity().unwrap()).is_err());
    }

    #[test]
    fn generation_and_registration_cannot_miss_removal() {
        let ca = generate_ca_material("root", 1);
        let pem = ca.1.self_signed(&ca.0).unwrap().pem();
        let cert = generate_workload(&ca, "spiffe://a/ns/n/sa/a");
        let map = bundle_map(&[("a", vec![pem.as_bytes()])]);
        let manager = TrustDomainManager::from_bundle_map(&map).unwrap();
        let (old_generation, _) = manager.selected(&cert.identity().unwrap()).unwrap();
        manager.set(HashMap::new(), false);
        assert!(manager.check_generation(old_generation).is_err());
        let late = manager.register(
            cert.identity().unwrap(),
            cert.cert_and_intermediates_der(),
            KeyUsage::client_auth(),
        );
        assert!(*late.subscribe().borrow());
        // Exercise simultaneous lock orders: whichever wins, registration either closes immediately
        // or becomes tracked before reload and receives the removal signal.
        for _ in 0..32 {
            manager.set(parse(&map).unwrap(), false);
            let m = manager.clone();
            let id = cert.identity().unwrap();
            let chain = cert.cert_and_intermediates_der();
            let worker = std::thread::spawn(move || m.register(id, chain, KeyUsage::server_auth()));
            manager.set(HashMap::new(), false);
            let handle = worker.join().unwrap();
            assert!(*handle.subscribe().borrow());
            assert_eq!(manager.inner.conns.lock().unwrap().entries.len(), 0);
        }
        manager.set(parse(&map).unwrap(), false);
        let handle = manager.register(
            cert.identity().unwrap(),
            cert.cert_and_intermediates_der(),
            KeyUsage::client_auth(),
        );
        assert_eq!(manager.inner.conns.lock().unwrap().entries.len(), 1);
        drop(handle);
        assert_eq!(manager.inner.conns.lock().unwrap().entries.len(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn native_parent_watcher_follows_configmap_data_symlink() {
        use std::os::unix::fs::symlink;
        let ca = generate_ca_material("root", 1);
        let pem = ca.1.self_signed(&ca.0).unwrap().pem();
        let peer = generate_workload(&ca, "spiffe://a/ns/n/sa/a")
            .identity()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("v1")).unwrap();
        std::fs::create_dir(dir.path().join("v2")).unwrap();
        std::fs::write(
            dir.path().join("v1/map.json"),
            bundle_map(&[("a", vec![pem.as_bytes()])]),
        )
        .unwrap();
        std::fs::write(dir.path().join("v2/map.json"), bundle_map(&[])).unwrap();
        symlink("v1", dir.path().join("..data")).unwrap();
        symlink("..data/map.json", dir.path().join("map.json")).unwrap();
        let manager = TrustDomainManager::new(dir.path().join("map.json"));
        manager.start_file_watcher().unwrap();
        assert!(manager.selected(&peer).is_ok());
        symlink("v2", dir.path().join("..data_tmp")).unwrap();
        std::fs::rename(dir.path().join("..data_tmp"), dir.path().join("..data")).unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while manager.selected(&peer).is_ok() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("atomic projection must reload without restart");
    }
}
