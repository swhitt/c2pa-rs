// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

use std::sync::Arc;

use c2pa_raw_crypto::{signer_from_private_key, RawSigner, RawSignerError, SigningAlg};
use http::Request;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::cert_chain_pem_to_der,
    dynamic_assertion::DynamicAssertion,
    http::{SyncGenericResolver, SyncHttpResolver},
    identity::{
        builder::{CredentialHolder, IdentityAssertionBuilder, IdentityBuilderError},
        x509::X509CredentialHolder,
        SignerPayload,
    },
    settings::{Settings, SettingsValidate},
    signer::{OwnedSignerWrapper, RawSignerWrapper},
    BoxedSigner, Error, Result, Signer,
};

/// One HTTP header to send with every RFC 3161 time stamp request made by a
/// signer configured from settings (see [`SignerSettings`]).
///
/// Use this to authenticate to a time stamp authority (TSA) that requires an
/// API key or bearer token. Exactly one of `value` or `from_env` must be set:
///
/// * `value` holds the header value inline. Use it for non-secret headers.
/// * `from_env` names an environment variable that is read when the signer is
///   created. Use it for secrets so they never appear in the settings file.
///
/// `format` optionally wraps the resolved value and must contain the
/// placeholder `{value}`. This lets the environment variable hold just the
/// token while the settings file supplies the scheme, e.g. `"Bearer {value}"`.
///
/// `Content-Type` cannot be set here: the SDK always sends
/// `application/timestamp-query`, as required by [RFC 3161].
///
/// # Example
///
/// ```toml
/// [signer.local]
/// alg = "es256"
/// sign_cert = "..."
/// private_key = "..."
/// tsa_url = "https://tsa.example.com"
///
/// [[signer.local.tsa_headers]]
/// name = "X-Tenant"
/// value = "acme-prod"
///
/// [[signer.local.tsa_headers]]
/// name = "Authorization"
/// from_env = "C2PA_TSA_AUTH_TOKEN"
/// format = "Bearer {value}"
/// ```
///
/// With `C2PA_TSA_AUTH_TOKEN=abc123` in the environment, the TSA receives
/// `Authorization: Bearer abc123`.
///
/// [RFC 3161]: https://datatracker.ietf.org/doc/html/rfc3161
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct TsaHeader {
    /// HTTP header name, for example `Authorization`.
    pub name: String,
    /// Inline header value. Mutually exclusive with `from_env`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Name of an environment variable holding the header value, read when the
    /// signer is created. Mutually exclusive with `value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_env: Option<String>,
    /// Optional template applied to the resolved value. Must contain `{value}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

impl TsaHeader {
    /// Placeholder in [`format`](Self::format) that is replaced by the resolved value.
    pub const VALUE_PLACEHOLDER: &'static str = "{value}";

    /// Creates a header with an inline (non-secret) value.
    pub fn with_value(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
            from_env: None,
            format: None,
        }
    }

    /// Creates a header whose value is read from the environment variable `var`
    /// when the signer is created.
    pub fn from_env(name: impl Into<String>, var: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: None,
            from_env: Some(var.into()),
            format: None,
        }
    }

    /// Wraps the resolved value in `format`, which must contain
    /// [`VALUE_PLACEHOLDER`](Self::VALUE_PLACEHOLDER).
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = Some(format.into());
        self
    }

    /// Checks that this header definition is well formed, without reading the
    /// environment.
    ///
    /// Settings loading calls this automatically. It fails if `name` is not a
    /// valid HTTP header name or is `Content-Type`, if neither or both of
    /// `value` and `from_env` are set, if `format` lacks the `{value}`
    /// placeholder, or if an inline `value` is not a valid HTTP header value.
    pub fn validate(&self) -> Result<()> {
        http::header::HeaderName::from_bytes(self.name.as_bytes()).map_err(|_| {
            Error::BadParam(format!(
                "tsa_headers: `{}` is not a valid HTTP header name",
                self.name
            ))
        })?;
        if self
            .name
            .eq_ignore_ascii_case(http::header::CONTENT_TYPE.as_str())
        {
            return Err(Error::BadParam(
                "tsa_headers: `Content-Type` is set by the SDK and cannot be overridden".to_owned(),
            ));
        }
        match (&self.value, &self.from_env) {
            (Some(_), Some(_)) => {
                return Err(Error::BadParam(format!(
                    "tsa_headers: header `{}` sets both `value` and `from_env`; use exactly one",
                    self.name
                )))
            }
            (None, None) => return Err(self.missing_source_error()),
            _ => {}
        }
        if let Some(format) = &self.format {
            if !format.contains(Self::VALUE_PLACEHOLDER) {
                return Err(Error::BadParam(format!(
                    "tsa_headers: `format` for header `{}` must contain the `{}` placeholder",
                    self.name,
                    Self::VALUE_PLACEHOLDER
                )));
            }
        }
        // Inline values can be checked now; `from_env` values only once resolved.
        if let Some(value) = &self.value {
            Self::check_header_value(&self.name, &self.apply_format(value))?;
        }
        Ok(())
    }

    /// Resolves this header to a `(name, value)` pair, reading the environment
    /// if `from_env` is set.
    ///
    /// Fails if the definition is invalid (see [`validate`](Self::validate)), if
    /// the environment variable is unset or not valid Unicode, or if the final
    /// value is not a valid HTTP header value (for example, it contains a line
    /// break). Error messages never include the header value.
    pub fn resolve(&self) -> Result<(String, String)> {
        self.validate()?;
        let raw = if let Some(value) = &self.value {
            value.clone()
        } else if let Some(var) = &self.from_env {
            std::env::var(var).map_err(|err| {
                let reason = match err {
                    std::env::VarError::NotPresent => "is not set",
                    std::env::VarError::NotUnicode(_) => "is not valid Unicode",
                };
                Error::BadParam(format!(
                    "tsa_headers: environment variable `{var}` for header `{}` {reason}",
                    self.name
                ))
            })?
        } else {
            return Err(self.missing_source_error());
        };
        let value = self.apply_format(&raw);
        Self::check_header_value(&self.name, &value)?;
        Ok((self.name.clone(), value))
    }

    fn apply_format(&self, raw: &str) -> String {
        match &self.format {
            Some(format) => format.replace(Self::VALUE_PLACEHOLDER, raw),
            None => raw.to_owned(),
        }
    }

    /// Rejects values that `http` would refuse (control characters such as CR/LF),
    /// so a misconfigured secret can't inject extra header lines. The value itself
    /// is deliberately kept out of the error.
    fn check_header_value(name: &str, value: &str) -> Result<()> {
        http::header::HeaderValue::from_str(value).map_err(|_| {
            Error::BadParam(format!(
                "tsa_headers: the value for header `{name}` is not a valid HTTP header value"
            ))
        })?;
        Ok(())
    }

    fn missing_source_error(&self) -> Error {
        Error::BadParam(format!(
            "tsa_headers: header `{}` must set either `value` or `from_env`",
            self.name
        ))
    }
}

/// Resolves `tsa_headers` into the `(name, value)` pairs returned by
/// [`Signer::timestamp_request_headers`]. An absent or empty list resolves to
/// `None`, so signers without headers behave exactly as before.
fn resolve_tsa_headers(headers: Option<&[TsaHeader]>) -> Result<Option<Vec<(String, String)>>> {
    match headers {
        None | Some([]) => Ok(None),
        Some(headers) => headers
            .iter()
            .map(TsaHeader::resolve)
            .collect::<Result<Vec<_>>>()
            .map(Some),
    }
}

/// Settings for configuring a local or remote [`Signer`].
///
/// A [`Signer`] can be obtained by calling the [`signer()`] function.
///
/// [`Signer`]: crate::Signer
/// [`signer()`]: crate::settings::Settings::signer
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignerSettings {
    /// A signer configured locally.
    Local {
        /// Algorithm to use for signing.
        #[cfg_attr(feature = "json_schema", schemars(with = "crate::SigningAlgSchema"))]
        alg: SigningAlg,
        /// Certificate used for signing (PEM format).
        sign_cert: String,
        /// Private key used for signing (PEM format).
        private_key: String,
        /// Time stamp authority URL for signing.
        tsa_url: Option<String>,
        /// Additional HTTP headers to send with each time stamp authority request,
        /// for example to authenticate (optional). See [`TsaHeader`].
        tsa_headers: Option<Vec<TsaHeader>>,
        /// Referenced assertions for CAWG identity signing (optional).
        referenced_assertions: Option<Vec<String>>,
        /// Roles for CAWG identity signing (optional).
        roles: Option<Vec<String>>,
    },
    /// A signer configured remotely.
    Remote {
        /// URL that the signer will use for signing.
        /// A POST request with a byte-stream will be sent to this URL.
        url: String,
        /// Algorithm to use for signing.
        #[cfg_attr(feature = "json_schema", schemars(with = "crate::SigningAlgSchema"))]
        alg: SigningAlg,
        /// Certificate used for signing (PEM format).
        sign_cert: String,
        /// Time stamp authority URL for signing.
        tsa_url: Option<String>,
        /// Additional HTTP headers to send with each time stamp authority request,
        /// for example to authenticate (optional). See [`TsaHeader`].
        tsa_headers: Option<Vec<TsaHeader>>,
        /// Referenced assertions for CAWG identity signing (optional).
        referenced_assertions: Option<Vec<String>>,
        /// Roles for CAWG identity signing (optional).
        roles: Option<Vec<String>>,
    },
}

impl SignerSettings {
    // TODO: add async signer
    /// Returns the constructed signer from the thread-local `signer` settings field.
    ///
    /// If the signer settings aren't specified, this function will return [Error::MissingSignerSettings].
    ///
    /// Configure the signer via a [`Context`](crate::Context) passed explicitly to
    /// [`Builder::from_context`](crate::Builder::from_context) instead.
    #[deprecated(
        note = "Configure the signer via `Context` and pass it to `Builder::from_context` instead of using thread-local signer settings. Will be removed in 0.92.0 (scheduled for mid-November 2026)."
    )]
    pub fn signer() -> Result<BoxedSigner> {
        let signer_info = match Settings::get_thread_local_value::<Option<SignerSettings>>("signer")
        {
            Ok(Some(signer_info)) => signer_info,
            #[cfg(test)]
            _ => {
                return Ok(crate::utils::test_signer::test_signer(SigningAlg::Ps256));
            }
            #[cfg(not(test))]
            _ => {
                return Err(Error::MissingSignerSettings);
            }
        };

        let c2pa_signer = Self::c2pa_signer(signer_info)?;

        // TO DISCUSS: What if get_value returns an Err(...)?
        if let Ok(Some(cawg_x509_settings)) =
            Settings::get_thread_local_value::<Option<SignerSettings>>("cawg_x509_signer")
        {
            cawg_x509_settings.cawg_signer(c2pa_signer)
        } else {
            Ok(c2pa_signer)
        }
    }

    /// Returns a c2pa signer using the provided signer settings.
    pub fn c2pa_signer(self) -> Result<BoxedSigner> {
        match self {
            SignerSettings::Local {
                alg,
                sign_cert,
                private_key,
                tsa_url,
                tsa_headers,
                referenced_assertions: _,
                roles: _,
            } => {
                let tsa_headers = resolve_tsa_headers(tsa_headers.as_deref())?;
                let signer = RawSignerWrapper::new(
                    signer_from_private_key(private_key.as_bytes(), alg)?,
                    cert_chain_pem_to_der(sign_cert.as_bytes())?,
                    tsa_url,
                )
                .with_time_stamp_request_headers(tsa_headers);
                Ok(Box::new(signer))
            }
            SignerSettings::Remote {
                url,
                alg,
                sign_cert,
                tsa_url,
                tsa_headers,
                referenced_assertions: _,
                roles: _,
            } => {
                let tsa_headers = resolve_tsa_headers(tsa_headers.as_deref())?;
                let certs = cert_chain_pem_to_der(sign_cert.as_bytes())?;
                let reserve_size = 10000 + certs.iter().map(|c| c.len()).sum::<usize>();
                Ok(Box::new(RemoteSigner {
                    url,
                    alg,
                    reserve_size,
                    certs,
                    tsa_url,
                    tsa_headers,
                }))
            }
        }
    }

    /// Returns a CAWG X.509 identity signer that wraps the provided c2pa signer.
    pub fn cawg_signer(self, c2pa_signer: BoxedSigner) -> Result<BoxedSigner> {
        match self {
            SignerSettings::Local {
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                private_key: cawg_private_key,
                tsa_url: cawg_tsa_url,
                // Like the TSA URL, unused: the identity signature is not time stamped.
                tsa_headers: _,
                referenced_assertions: cawg_referenced_assertions,
                roles: cawg_roles,
            } => {
                let signer = CawgX509IdentitySigner::from_settings(
                    c2pa_signer,
                    cawg_alg,
                    cawg_sign_cert.as_bytes(),
                    cawg_private_key.as_bytes(),
                    cawg_tsa_url,
                    cawg_referenced_assertions.unwrap_or_default(),
                    cawg_roles.unwrap_or_default(),
                )?;
                Ok(Box::new(signer))
            }

            SignerSettings::Remote {
                url,
                alg: cawg_alg,
                sign_cert: cawg_sign_cert,
                tsa_url: cawg_tsa_url,
                // Like the TSA URL, unused: the identity signature is not time stamped.
                tsa_headers: _,
                referenced_assertions: cawg_referenced_assertions,
                roles: cawg_roles,
            } => {
                // The identity (CAWG) signature is not RFC 3161 time stamped, so
                // the TSA URL is intentionally unused here (matches the Local case).
                let _ = cawg_tsa_url;

                let signer = CawgX509IdentitySigner::from_remote_settings(
                    c2pa_signer,
                    cawg_alg,
                    url,
                    cawg_sign_cert.as_bytes(),
                    cawg_referenced_assertions.unwrap_or_default(),
                    cawg_roles.unwrap_or_default(),
                )?;
                Ok(Box::new(signer))
            }
        }
    }
}

impl SettingsValidate for SignerSettings {
    fn validate(&self) -> Result<()> {
        let (SignerSettings::Local { tsa_headers, .. }
        | SignerSettings::Remote { tsa_headers, .. }) = self;
        for header in tsa_headers.iter().flatten() {
            header.validate()?;
        }
        Ok(())
    }
}

/// Wraps an `Arc<dyn RawSigner>` so it can be passed as an owned `Box<dyn RawSigner>`.
struct ArcRawSigner(Arc<dyn RawSigner + Send + Sync>);

impl RawSigner for ArcRawSigner {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        self.0.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.0.alg()
    }

    fn max_signature_size(&self) -> usize {
        self.0.max_signature_size()
    }
}

pub(crate) struct CawgX509IdentitySigner {
    c2pa_signer: BoxedSigner,
    identity_signer: Arc<dyn RawSigner + Send + Sync>,
    identity_cert_chain: Vec<Vec<u8>>,
    referenced_assertions: Vec<String>,
    roles: Vec<String>,
}

impl CawgX509IdentitySigner {
    /// Creates a combined signer from cert/key bytes for the identity signer.
    pub(crate) fn from_settings(
        c2pa_signer: BoxedSigner,
        alg: SigningAlg,
        sign_cert: &[u8],
        private_key: &[u8],
        tsa_url: Option<String>,
        referenced_assertions: Vec<String>,
        roles: Vec<String>,
    ) -> Result<Self> {
        // The identity (CAWG) signature is not RFC 3161 time stamped, so the TSA
        // URL is intentionally unused here.
        let _ = tsa_url;
        let raw_signer = signer_from_private_key(private_key, alg)?;
        Ok(Self {
            c2pa_signer,
            identity_signer: Arc::from(raw_signer),
            identity_cert_chain: cert_chain_pem_to_der(sign_cert)?,
            referenced_assertions,
            roles,
        })
    }

    /// Creates a combined signer that delegates identity signing to a remote
    /// HTTP endpoint.
    pub(crate) fn from_remote_settings(
        c2pa_signer: BoxedSigner,
        alg: SigningAlg,
        url: String,
        sign_cert: &[u8],
        referenced_assertions: Vec<String>,
        roles: Vec<String>,
    ) -> Result<Self> {
        let identity_cert_chain = cert_chain_pem_to_der(sign_cert)?;

        // `max_signature_size` must describe only the raw signature: the cert chain
        // is already accounted for separately by `X509CredentialHolder::reserve_size()`
        // (via `cose_reserve_size`). 10_000 bytes is a generous fixed upper bound since
        // the remote endpoint's exact signature size isn't known locally.
        let max_signature_size = 10_000;

        Ok(Self {
            c2pa_signer,
            identity_signer: Arc::new(RemoteRawSigner {
                url,
                alg,
                max_signature_size,
            }),
            identity_cert_chain,
            referenced_assertions,
            roles,
        })
    }

    /// Creates a combined signer from an already-constructed identity [`Signer`].
    pub(crate) fn from_signer(
        c2pa_signer: BoxedSigner,
        identity_signer: BoxedSigner,
        referenced_assertions: &[&str],
        roles: &[&str],
    ) -> Self {
        let identity_cert_chain = identity_signer.certs().unwrap_or_default();
        Self {
            c2pa_signer,
            identity_signer: Arc::new(OwnedSignerWrapper(identity_signer)),
            identity_cert_chain,
            referenced_assertions: referenced_assertions
                .iter()
                .map(|s| s.to_string())
                .collect(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Signer for CawgX509IdentitySigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Signer::sign(&self.c2pa_signer, data)
    }

    fn alg(&self) -> SigningAlg {
        Signer::alg(&self.c2pa_signer)
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.c2pa_signer.certs()
    }

    fn reserve_size(&self) -> usize {
        Signer::reserve_size(&self.c2pa_signer)
    }

    fn time_authority_url(&self) -> Option<String> {
        self.c2pa_signer.time_authority_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.c2pa_signer.timestamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.c2pa_signer.timestamp_request_body(message)
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.c2pa_signer.send_timestamp_request(message)
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.c2pa_signer.ocsp_val()
    }

    fn direct_cose_handling(&self) -> bool {
        self.c2pa_signer.direct_cose_handling()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        let identity_signer: Box<dyn RawSigner + Sync + Send + 'static> =
            Box::new(ArcRawSigner(Arc::clone(&self.identity_signer)));
        let x509_credential_holder = X509CredentialHolder::from_raw_signer(
            identity_signer,
            self.identity_cert_chain.clone(),
        );

        let mut iab = IdentityAssertionBuilder::for_credential_holder(x509_credential_holder);

        if !self.referenced_assertions.is_empty() {
            let refs: Vec<&str> = self
                .referenced_assertions
                .iter()
                .map(|s| s.as_str())
                .collect();
            iab.add_referenced_assertions(&refs);
        }

        if !self.roles.is_empty() {
            let roles: Vec<&str> = self.roles.iter().map(|s| s.as_str()).collect();
            iab.add_roles(&roles);
        }

        vec![Box::new(iab)]
    }
}

/// Shares one [`CredentialHolder`] between the identity assertion builders
/// handed out on every [`Signer::dynamic_assertions`] call.
struct ArcCredentialHolder(Arc<dyn CredentialHolder + Send + Sync>);

impl CredentialHolder for ArcCredentialHolder {
    fn sig_type(&self) -> &'static str {
        self.0.sig_type()
    }

    fn reserve_size(&self) -> usize {
        self.0.reserve_size()
    }

    fn sign(
        &self,
        signer_payload: &SignerPayload,
    ) -> std::result::Result<Vec<u8>, IdentityBuilderError> {
        self.0.sign(signer_payload)
    }
}

/// A [`Signer`] that signs the C2PA claim with an inner signer and adds one
/// CAWG identity assertion produced by an arbitrary [`CredentialHolder`]
/// (for example an identity claims aggregation credential fetched from an
/// issuer at signing time).
///
/// Unlike [`CawgX509IdentitySigner`], this wrapper keeps whatever dynamic
/// assertions the inner signer already contributes, so wrapping an X.509
/// identity signer yields a manifest with both identity assertions.
pub(crate) struct CawgIdentitySigner {
    c2pa_signer: BoxedSigner,
    credential_holder: Arc<dyn CredentialHolder + Send + Sync>,
    referenced_assertions: Vec<String>,
    roles: Vec<String>,
}

impl CawgIdentitySigner {
    pub(crate) fn new(
        c2pa_signer: BoxedSigner,
        credential_holder: Box<dyn CredentialHolder + Send + Sync>,
        referenced_assertions: &[&str],
        roles: &[&str],
    ) -> Self {
        Self {
            c2pa_signer,
            credential_holder: Arc::from(credential_holder),
            referenced_assertions: referenced_assertions
                .iter()
                .map(|s| s.to_string())
                .collect(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Signer for CawgIdentitySigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Signer::sign(&self.c2pa_signer, data)
    }

    fn alg(&self) -> SigningAlg {
        Signer::alg(&self.c2pa_signer)
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        self.c2pa_signer.certs()
    }

    fn reserve_size(&self) -> usize {
        Signer::reserve_size(&self.c2pa_signer)
    }

    fn time_authority_url(&self) -> Option<String> {
        self.c2pa_signer.time_authority_url()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.c2pa_signer.timestamp_request_headers()
    }

    fn timestamp_request_body(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.c2pa_signer.timestamp_request_body(message)
    }

    fn send_timestamp_request(&self, message: &[u8]) -> Option<Result<Vec<u8>>> {
        self.c2pa_signer.send_timestamp_request(message)
    }

    fn ocsp_val(&self) -> Option<Vec<u8>> {
        self.c2pa_signer.ocsp_val()
    }

    fn direct_cose_handling(&self) -> bool {
        self.c2pa_signer.direct_cose_handling()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        let mut assertions = self.c2pa_signer.dynamic_assertions();

        let mut iab = IdentityAssertionBuilder::for_credential_holder(ArcCredentialHolder(
            Arc::clone(&self.credential_holder),
        ));

        if !self.referenced_assertions.is_empty() {
            let refs: Vec<&str> = self
                .referenced_assertions
                .iter()
                .map(|s| s.as_str())
                .collect();
            iab.add_referenced_assertions(&refs);
        }

        if !self.roles.is_empty() {
            let roles: Vec<&str> = self.roles.iter().map(|s| s.as_str()).collect();
            iab.add_roles(&roles);
        }

        assertions.push(Box::new(iab));
        assertions
    }
}

pub(crate) struct RemoteSigner {
    url: String,
    alg: SigningAlg,
    certs: Vec<Vec<u8>>,
    reserve_size: usize,
    tsa_url: Option<String>,
    tsa_headers: Option<Vec<(String, String)>>,
}

impl Signer for RemoteSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use std::io::Read;

        let request = Request::post(&self.url).body(data.to_vec())?;
        let response = SyncGenericResolver::with_redirects()
            .unwrap_or_default()
            .http_resolve(request)
            .map_err(|_| Error::FailedToRemoteSign)?;
        let mut bytes: Vec<u8> = Vec::with_capacity(self.reserve_size);
        response
            .into_body()
            .take(self.reserve_size as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn certs(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.certs.clone())
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        self.tsa_url.clone()
    }

    fn timestamp_request_headers(&self) -> Option<Vec<(String, String)>> {
        self.tsa_headers.clone()
    }
}

/// A [`RawSigner`] that delegates identity signing to a remote HTTP endpoint.
///
/// A POST request with the raw bytes-to-be-signed as the body is sent to
/// `url`; the response body (up to `max_signature_size` bytes) is used as
/// the raw signature. This mirrors [`RemoteSigner`], but implements the
/// lower-level [`RawSigner`] trait so it can back a [`CawgX509IdentitySigner`]
/// (whose certificate chain and reserve-size accounting are handled by the
/// SDK, not the raw signer).
#[derive(Debug)]
struct RemoteRawSigner {
    url: String,
    alg: SigningAlg,
    max_signature_size: usize,
}

impl RawSigner for RemoteRawSigner {
    fn sign(&self, data: &[u8]) -> std::result::Result<Vec<u8>, RawSignerError> {
        use std::io::Read;

        let request = Request::post(&self.url)
            .body(data.to_vec())
            .map_err(|e| RawSignerError::InternalError(e.to_string()))?;
        let response = SyncGenericResolver::with_redirects()
            .unwrap_or_default()
            .http_resolve(request)
            .map_err(|e| RawSignerError::InternalError(e.to_string()))?;

        let mut bytes: Vec<u8> = Vec::with_capacity(self.max_signature_size);
        response
            .into_body()
            .take(self.max_signature_size as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| RawSignerError::InternalError(e.to_string()))?;
        Ok(bytes)
    }

    fn alg(&self) -> SigningAlg {
        self.alg
    }

    fn max_signature_size(&self) -> usize {
        self.max_signature_size
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]

    #[cfg(not(target_arch = "wasm32"))]
    use crate::BoxedSigner;
    use crate::{settings::Settings, utils::test_signer, Signer, SigningAlg};

    #[cfg(not(target_arch = "wasm32"))]
    fn remote_signer_mock_server<'a>(
        server: &'a httpmock::MockServer,
        signed_bytes: &[u8],
    ) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(httpmock::Method::POST);
            then.status(200).body(signed_bytes);
        })
    }

    /// Mocks a remote signing endpoint that signs whatever bytes it receives
    /// using a local reference `signer`, simulating a real remote signing
    /// service backed by a private key it never exposes.
    #[cfg(not(target_arch = "wasm32"))]
    fn remote_signer_respond_with_signature(
        server: &httpmock::MockServer,
        signer: BoxedSigner,
    ) -> httpmock::Mock<'_> {
        server.mock(|when, then| {
            when.method(httpmock::Method::POST);
            then.respond_with(move |req: &httpmock::HttpMockRequest| {
                let signed = signer.sign(req.body_ref()).unwrap_or_default();
                http::Response::builder()
                    .status(200)
                    .body(signed)
                    .unwrap()
                    .into()
            });
        })
    }

    /// Legacy test verifying the deprecated thread-local signer API still works.
    #[test]
    #[allow(deprecated)]
    fn test_thread_local_signer() {
        assert!(Settings::signer().is_ok());
    }

    #[test]
    fn test_make_local_signer() {
        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.local]
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                    private_key = (String::from_utf8(private_key.to_vec()).unwrap())
                }
                .to_string(),
            )
            .unwrap();

        // Test the settings signer path directly (context.signer() uses a custom test
        // signer in test mode, so we test SignerSettings::c2pa_signer() directly here)
        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.time_authority_url(), None);
        assert_eq!(signer.timestamp_request_headers(), None);
        assert!(signer.sign(&[1, 2, 3]).is_ok());
    }

    #[test]
    fn test_make_cawg_local_signer_from_settings() {
        let alg = SigningAlg::Ed25519;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.local]
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                    private_key = (String::from_utf8(private_key.to_vec()).unwrap())

                    [cawg_x509_signer.local]
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                    private_key = (String::from_utf8(private_key.to_vec()).unwrap())
                    referenced_assertions = ["c2pa.actions"]
                    roles = ["creator"]
                }
                .to_string(),
            )
            .unwrap();

        let c2pa_settings = settings.signer.expect("signer settings should be present");
        let c2pa_signer = c2pa_settings.c2pa_signer().unwrap();

        let cawg_settings = settings
            .cawg_x509_signer
            .expect("cawg signer settings should be present");
        let combined = cawg_settings.cawg_signer(c2pa_signer).unwrap();

        // Verify the combined signer delegates alg/certs to the underlying c2pa signer.
        assert_eq!(combined.alg(), alg);
        assert!(!combined.certs().unwrap().is_empty());
        // The combined signer produces dynamic assertions (the identity assertion builder).
        assert_eq!(combined.dynamic_assertions().len(), 1);
    }

    #[test]
    fn test_cawg_identity_signer_from_signer_path() {
        use crate::{create_signer, settings::signer::CawgX509IdentitySigner, Signer};

        let alg = SigningAlg::Ps256;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let c2pa_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let identity_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();

        let combined = CawgX509IdentitySigner::from_signer(
            c2pa_signer,
            identity_signer,
            &["c2pa.actions"],
            &["creator"],
        );

        assert_eq!(combined.alg(), alg);
        assert!(!combined.certs().unwrap().is_empty());
        assert_eq!(combined.dynamic_assertions().len(), 1);
        // Sign delegates to c2pa_signer, so it should succeed with valid data.
        assert!(combined.sign(b"test data").is_ok());
    }

    #[test]
    fn test_cawg_signer_no_referenced_assertions_or_roles() {
        use crate::{create_signer, settings::signer::CawgX509IdentitySigner};

        let alg = SigningAlg::Ps256;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let c2pa_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let identity_signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();

        let combined = CawgX509IdentitySigner::from_signer(c2pa_signer, identity_signer, &[], &[]);

        // dynamic_assertions still returns one builder even with empty refs/roles.
        assert_eq!(combined.dynamic_assertions().len(), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_remote_signer() {
        use httpmock::MockServer;

        use crate::create_signer;

        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let signed_bytes = signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_mock_server(&server, &signed_bytes);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = (server.base_url())
                    alg = (alg.to_string())
                    sign_cert = (String::from_utf8(sign_cert.to_vec()).unwrap())
                }
                .to_string(),
            )
            .unwrap();

        // Test the settings signer path directly (context.signer() uses a custom test
        // signer in test mode, so we test SignerSettings::c2pa_signer() directly here)
        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.time_authority_url(), None);
        assert_eq!(signer.timestamp_request_headers(), None);
        assert_eq!(signer.sign(&[1, 2, 3]).unwrap(), signed_bytes);

        mock.assert();

        // certs() must return DER-encoded certs (not raw PEM text), matching the
        // Local variant's behavior via create_signer::from_keys.
        let der_certs = signer.certs().unwrap();
        assert!(!der_certs.is_empty());
        let pem_text = String::from_utf8(sign_cert.to_vec()).unwrap();
        let expected_der = crate::crypto::cert_chain_pem_to_der(pem_text.as_bytes()).unwrap();
        assert_eq!(der_certs, expected_der);
        for der in &der_certs {
            assert_ne!(der.as_slice(), pem_text.as_bytes());
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_remote_signer_json_escaped_pem() {
        use httpmock::MockServer;

        use crate::create_signer;

        let alg = SigningAlg::Ps384;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);

        let signer = create_signer::from_keys(sign_cert, private_key, alg, None).unwrap();
        let signed_bytes = signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_mock_server(&server, &signed_bytes);

        // Simulate a cert chain delivered with literal "\n" escapes, as happens
        // when a PEM cert is embedded in a JSON config value.
        let pem_text = String::from_utf8(sign_cert.to_vec()).unwrap();
        let escaped_pem = pem_text.replace('\n', "\\n");

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = (server.base_url())
                    alg = (alg.to_string())
                    sign_cert = (escaped_pem)
                }
                .to_string(),
            )
            .unwrap();

        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.alg(), alg);
        assert_eq!(signer.sign(&[1, 2, 3]).unwrap(), signed_bytes);

        let der_certs = signer.certs().unwrap();
        assert!(!der_certs.is_empty());
        let expected_der = crate::crypto::cert_chain_pem_to_der(pem_text.as_bytes()).unwrap();
        assert_eq!(der_certs, expected_der);

        mock.assert();
    }

    #[test]
    fn test_make_remote_signer_malformed_pem_errors() {
        let alg = SigningAlg::Ps384;

        // Has BEGIN/END markers (so the parser attempts to decode a block) but
        // the body is not valid base64, so decoding must fail with an error
        // rather than silently producing an empty cert list.
        let malformed_pem =
            "-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n";

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = "https://example.com/sign"
                    alg = (alg.to_string())
                    sign_cert = (malformed_pem)
                }
                .to_string(),
            )
            .unwrap();

        let signer_settings = settings.signer.expect("signer settings should be present");
        assert!(signer_settings.c2pa_signer().is_err());
    }

    #[test]
    fn test_make_remote_signer_no_pem_blocks_yields_empty_certs() {
        // No BEGIN/END markers at all: the underlying parser treats this as
        // "no blocks found" and returns an empty cert list rather than an
        // error. This documents that behavior so a future change can't
        // silently alter it without a failing test.
        let alg = SigningAlg::Ps384;

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [signer.remote]
                    url = "https://example.com/sign"
                    alg = (alg.to_string())
                    sign_cert = "not a pem cert chain at all"
                }
                .to_string(),
            )
            .unwrap();

        let signer_settings = settings.signer.expect("signer settings should be present");
        let signer = signer_settings.c2pa_signer().unwrap();
        assert_eq!(signer.certs().unwrap(), Vec::<Vec<u8>>::new());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_make_cawg_remote_signer_from_settings() {
        use httpmock::MockServer;

        use crate::create_signer;

        let c2pa_alg = SigningAlg::Ps384;
        let (c2pa_sign_cert, c2pa_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(c2pa_alg);
        let c2pa_signer =
            create_signer::from_keys(c2pa_sign_cert, c2pa_private_key, c2pa_alg, None).unwrap();

        let cawg_alg = SigningAlg::Ed25519;
        let (cawg_sign_cert, cawg_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(cawg_alg);
        let reference_signer =
            create_signer::from_keys(cawg_sign_cert, cawg_private_key, cawg_alg, None).unwrap();
        let signed_bytes = reference_signer.sign(&[1, 2, 3]).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_mock_server(&server, &signed_bytes);

        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [cawg_x509_signer.remote]
                    url = (server.base_url())
                    alg = (cawg_alg.to_string())
                    sign_cert = (String::from_utf8(cawg_sign_cert.to_vec()).unwrap())
                    referenced_assertions = ["c2pa.actions"]
                    roles = ["creator"]
                }
                .to_string(),
            )
            .unwrap();

        let cawg_settings = settings
            .cawg_x509_signer
            .expect("cawg signer settings should be present");
        let combined = cawg_settings.cawg_signer(c2pa_signer).unwrap();

        // The combined signer still delegates alg/certs/sign to the underlying
        // c2pa signer; the remote identity signer only backs dynamic_assertions().
        assert_eq!(combined.alg(), c2pa_alg);
        assert!(!combined.certs().unwrap().is_empty());
        assert_eq!(combined.dynamic_assertions().len(), 1);

        // dynamic_assertions() only builds the assertion; it doesn't invoke the
        // remote identity signer yet, so the mock is intentionally not asserted
        // here (see test_cawg_remote_signer_round_trip for the full path).
        let _ = mock;
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[c2pa_macros::c2pa_test_async]
    async fn test_cawg_remote_signer_round_trip() {
        use std::io::{Cursor, Seek};

        use httpmock::MockServer;

        use crate::{
            create_signer,
            crypto::cose::Verifier,
            identity::{
                tests::fixtures::{manifest_json, parent_json},
                x509::X509SignatureVerifier,
                IdentityAssertion,
            },
            status_tracker::StatusTracker,
            Builder, Reader,
        };

        const TEST_IMAGE: &[u8] = include_bytes!("../../tests/fixtures/CA.jpg");
        const TEST_THUMBNAIL: &[u8] = include_bytes!("../../tests/fixtures/thumbnail.jpg");

        let format = "image/jpeg";
        let mut source = Cursor::new(TEST_IMAGE);
        let mut dest = Cursor::new(Vec::new());

        let c2pa_alg = SigningAlg::Ps256;
        let (c2pa_sign_cert, c2pa_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(c2pa_alg);
        let c2pa_signer =
            create_signer::from_keys(c2pa_sign_cert, c2pa_private_key, c2pa_alg, None).unwrap();

        let cawg_alg = SigningAlg::Ed25519;
        let (cawg_sign_cert, cawg_private_key) =
            test_signer::cert_chain_and_private_key_for_alg(cawg_alg);
        // The "remote" endpoint is backed by a local signer holding the same
        // private key, simulating a real remote signing service.
        let reference_identity_signer =
            create_signer::from_keys(cawg_sign_cert, cawg_private_key, cawg_alg, None).unwrap();

        let server = MockServer::start();
        let mock = remote_signer_respond_with_signature(&server, reference_identity_signer);

        // decode_identity_assertions is disabled so IdentityAssertion::from_manifest
        // below can parse the raw assertion content itself (matches the pattern used
        // by other CAWG X.509 round-trip tests in sdk/src/identity/x509).
        let settings = Settings::new()
            .with_toml(
                &toml::toml! {
                    [cawg_x509_signer.remote]
                    url = (server.base_url())
                    alg = (cawg_alg.to_string())
                    sign_cert = (String::from_utf8(cawg_sign_cert.to_vec()).unwrap())
                    referenced_assertions = ["c2pa.actions"]
                    roles = ["creator"]
                }
                .to_string(),
            )
            .unwrap()
            .with_value("core.decode_identity_assertions", false)
            .unwrap();

        let cawg_settings = settings
            .cawg_x509_signer
            .clone()
            .expect("cawg signer settings should be present");
        let combined_signer = cawg_settings.cawg_signer(c2pa_signer).unwrap();

        let context = crate::Context::new()
            .with_settings(settings)
            .unwrap()
            .into_shared();

        let mut builder = Builder::from_shared_context(&context)
            .with_definition(manifest_json())
            .unwrap();
        builder
            .add_ingredient_from_stream(parent_json(), format, &mut source)
            .unwrap();
        builder
            .add_resource("thumbnail.jpg", Cursor::new(TEST_THUMBNAIL))
            .unwrap();

        builder
            .sign(&combined_signer, format, &mut source, &mut dest)
            .unwrap();

        mock.assert();

        dest.rewind().unwrap();
        let manifest_store = Reader::from_shared_context(&context)
            .with_stream(format, &mut dest)
            .unwrap();
        assert_eq!(manifest_store.validation_status(), None);

        let manifest = manifest_store.active_manifest().unwrap();
        let mut st = StatusTracker::default();
        let mut ia_iter = IdentityAssertion::from_manifest(manifest, &mut st);

        let ia = ia_iter.next().unwrap().unwrap();
        assert!(ia_iter.next().is_none());
        drop(ia_iter);

        let x509_verifier = X509SignatureVerifier {
            cose_verifier: Verifier::IgnoreProfileAndTrustPolicy,
        };
        let sig_info = ia
            .validate(manifest, &mut st, &x509_verifier)
            .await
            .unwrap();

        assert_eq!(sig_info.cert_info.alg.unwrap(), cawg_alg);
    }

    // ---- tsa_headers --------------------------------------------------------

    /// Settings for a local signer pointing at `tsa_url` with the given
    /// `tsa_headers` JSON array.
    fn local_signer_settings_with_tsa_headers(
        tsa_url: &str,
        tsa_headers: serde_json::Value,
    ) -> crate::Result<Settings> {
        let alg = SigningAlg::Es256;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);
        Settings::new().with_json(
            &serde_json::json!({
                "signer": {
                    "local": {
                        "alg": alg.to_string(),
                        "sign_cert": String::from_utf8_lossy(sign_cert),
                        "private_key": String::from_utf8_lossy(private_key),
                        "tsa_url": tsa_url,
                        "tsa_headers": tsa_headers,
                    }
                }
            })
            .to_string(),
        )
    }

    fn c2pa_signer_from(settings: Settings) -> crate::Result<crate::BoxedSigner> {
        settings
            .signer
            .expect("signer settings should be present")
            .c2pa_signer()
    }

    /// Error message from building the signer from `settings`, which must fail.
    #[cfg(not(target_arch = "wasm32"))]
    fn c2pa_signer_error(settings: Settings) -> String {
        c2pa_signer_from(settings)
            .err()
            .map(|err| err.to_string())
            .expect("building the signer should fail")
    }

    /// Error message from loading local signer settings with the given `tsa_headers`.
    fn tsa_headers_load_error(tsa_headers: serde_json::Value) -> String {
        local_signer_settings_with_tsa_headers("https://tsa.example.com", tsa_headers)
            .expect_err("settings with malformed tsa_headers should not load")
            .to_string()
    }

    /// Sets an environment variable for the duration of a test and removes it on
    /// drop, so a failing assertion can't leak state into other tests. Each test
    /// uses a distinct variable name because tests run in parallel.
    #[cfg(not(target_arch = "wasm32"))]
    struct EnvVarGuard(&'static str);

    #[cfg(not(target_arch = "wasm32"))]
    impl EnvVarGuard {
        fn set(name: &'static str, value: &str) -> Self {
            std::env::set_var(name, value);
            Self(name)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    fn tsa_headers_empty_list_yields_none() {
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([]),
        )
        .unwrap();
        let signer = c2pa_signer_from(settings).unwrap();
        assert_eq!(signer.timestamp_request_headers(), None);
    }

    #[test]
    fn tsa_headers_inline_values_keep_order_and_apply_format() {
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([
                { "name": "X-Tenant", "value": "acme-prod" },
                { "name": "X-Api-Key", "value": "k-123", "format": "Key {value}" },
            ]),
        )
        .unwrap();
        let signer = c2pa_signer_from(settings).unwrap();
        assert_eq!(
            signer.timestamp_request_headers(),
            Some(vec![
                ("X-Tenant".to_owned(), "acme-prod".to_owned()),
                ("X-Api-Key".to_owned(), "Key k-123".to_owned()),
            ])
        );
    }

    /// The documented TOML array-of-tables form (`[[signer.local.tsa_headers]]`).
    #[test]
    fn tsa_headers_toml_array_of_tables() {
        let alg = SigningAlg::Es256;
        let (sign_cert, private_key) = test_signer::cert_chain_and_private_key_for_alg(alg);
        let toml = format!(
            r#"
[signer.local]
alg = "{alg}"
sign_cert = '''
{sign_cert}'''
private_key = '''
{private_key}'''
tsa_url = "https://tsa.example.com"

[[signer.local.tsa_headers]]
name = "X-Tenant"
value = "acme-prod"

[[signer.local.tsa_headers]]
name = "Authorization"
value = "Bearer inline-for-test"
"#,
            sign_cert = String::from_utf8_lossy(sign_cert),
            private_key = String::from_utf8_lossy(private_key),
        );
        let settings = Settings::new().with_toml(&toml).unwrap();
        let signer = c2pa_signer_from(settings).unwrap();
        assert_eq!(
            signer.timestamp_request_headers(),
            Some(vec![
                ("X-Tenant".to_owned(), "acme-prod".to_owned()),
                (
                    "Authorization".to_owned(),
                    "Bearer inline-for-test".to_owned()
                ),
            ])
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_headers_from_env_applies_format() {
        const VAR: &str = "C2PA_TEST_TSA_HEADERS_FORMAT";
        let _guard = EnvVarGuard::set(VAR, "abc123");
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([
                { "name": "Authorization", "from_env": VAR, "format": "Bearer {value}" },
            ]),
        )
        .unwrap();
        let signer = c2pa_signer_from(settings).unwrap();
        assert_eq!(
            signer.timestamp_request_headers(),
            Some(vec![(
                "Authorization".to_owned(),
                "Bearer abc123".to_owned()
            )])
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_headers_from_env_without_format_uses_raw_value() {
        const VAR: &str = "C2PA_TEST_TSA_HEADERS_RAW";
        let _guard = EnvVarGuard::set(VAR, "raw-token");
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([{ "name": "X-Api-Key", "from_env": VAR }]),
        )
        .unwrap();
        let signer = c2pa_signer_from(settings).unwrap();
        assert_eq!(
            signer.timestamp_request_headers(),
            Some(vec![("X-Api-Key".to_owned(), "raw-token".to_owned())])
        );
    }

    /// Loading settings must not read the environment: a verify-only process may
    /// load a shared settings file without ever having the signing secret. The
    /// missing variable is reported when the signer is actually created.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_headers_unset_env_var_fails_at_signer_creation_not_at_load() {
        const VAR: &str = "C2PA_TEST_TSA_HEADERS_UNSET";
        std::env::remove_var(VAR);
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([
                { "name": "Authorization", "from_env": VAR, "format": "Bearer {value}" },
            ]),
        )
        .expect("settings should load without reading the environment");

        let msg = c2pa_signer_error(settings);
        assert!(msg.contains(VAR), "{msg}");
        assert!(msg.contains("Authorization"), "{msg}");
    }

    /// A secret containing CR/LF would otherwise let it inject extra header
    /// lines; it is rejected, and the error must not echo the secret.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_headers_env_value_with_line_break_is_rejected_without_leaking_it() {
        const VAR: &str = "C2PA_TEST_TSA_HEADERS_CRLF";
        let _guard = EnvVarGuard::set(VAR, "abc\r\nX-Injected: 1");
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([{ "name": "Authorization", "from_env": VAR }]),
        )
        .unwrap();

        let msg = c2pa_signer_error(settings);
        assert!(msg.contains("Authorization"), "{msg}");
        assert!(
            !msg.contains("X-Injected"),
            "error must not echo the secret: {msg}"
        );
    }

    #[test]
    fn tsa_headers_reject_both_value_and_from_env() {
        let msg = tsa_headers_load_error(serde_json::json!([
            { "name": "Authorization", "value": "x", "from_env": "Y" },
        ]));
        assert!(msg.contains("exactly one"), "{msg}");
    }

    #[test]
    fn tsa_headers_reject_neither_value_nor_from_env() {
        let msg = tsa_headers_load_error(serde_json::json!([{ "name": "Authorization" }]));
        assert!(msg.contains("`value` or `from_env`"), "{msg}");
    }

    #[test]
    fn tsa_headers_reject_invalid_header_name() {
        let msg = tsa_headers_load_error(serde_json::json!([
            { "name": "X Tenant", "value": "acme" },
        ]));
        assert!(msg.contains("not a valid HTTP header name"), "{msg}");
    }

    /// `Content-Type` is owned by the SDK (RFC 3161 fixes it), in any letter case.
    #[test]
    fn tsa_headers_reject_content_type() {
        let msg = tsa_headers_load_error(serde_json::json!([
            { "name": "content-type", "value": "text/plain" },
        ]));
        assert!(msg.contains("Content-Type"), "{msg}");
    }

    /// A `format` without the placeholder would silently send a constant.
    #[test]
    fn tsa_headers_reject_format_without_placeholder() {
        let msg = tsa_headers_load_error(serde_json::json!([
            { "name": "Authorization", "value": "x", "format": "Bearer" },
        ]));
        assert!(msg.contains("{value}"), "{msg}");
    }

    #[test]
    fn tsa_headers_reject_inline_value_with_line_break() {
        let msg = tsa_headers_load_error(serde_json::json!([
            { "name": "X-Tenant", "value": "a\nb" },
        ]));
        assert!(msg.contains("not a valid HTTP header value"), "{msg}");
    }

    #[test]
    fn tsa_headers_remote_signer() {
        let alg = SigningAlg::Es256;
        let (sign_cert, _) = test_signer::cert_chain_and_private_key_for_alg(alg);
        let settings = Settings::new()
            .with_json(
                &serde_json::json!({
                    "signer": {
                        "remote": {
                            "url": "https://signing.example.com/sign",
                            "alg": alg.to_string(),
                            "sign_cert": String::from_utf8_lossy(sign_cert),
                            "tsa_url": "https://tsa.example.com",
                            "tsa_headers": [{ "name": "X-Api-Key", "value": "k-123" }],
                        }
                    }
                })
                .to_string(),
            )
            .unwrap();
        let signer = c2pa_signer_from(settings).unwrap();
        assert_eq!(
            signer.time_authority_url().as_deref(),
            Some("https://tsa.example.com")
        );
        assert_eq!(
            signer.timestamp_request_headers(),
            Some(vec![("X-Api-Key".to_owned(), "k-123".to_owned())])
        );
    }

    /// The CAWG wrapper forwards the C2PA signer's headers; its own
    /// `tsa_headers` are ignored, like `tsa_url` (the identity signature is not
    /// time stamped).
    #[test]
    fn tsa_headers_survive_cawg_wrapping() {
        let settings = local_signer_settings_with_tsa_headers(
            "https://tsa.example.com",
            serde_json::json!([{ "name": "X-Api-Key", "value": "k-123" }]),
        )
        .unwrap();
        let signer_settings = settings.signer.expect("signer settings should be present");
        let c2pa_signer = signer_settings.clone().c2pa_signer().unwrap();
        let combined = signer_settings.cawg_signer(c2pa_signer).unwrap();
        assert_eq!(
            combined.timestamp_request_headers(),
            Some(vec![("X-Api-Key".to_owned(), "k-123".to_owned())])
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_header_constructors_resolve() {
        use super::TsaHeader;

        assert_eq!(
            TsaHeader::with_value("X-Tenant", "acme").resolve().unwrap(),
            ("X-Tenant".to_owned(), "acme".to_owned())
        );

        const VAR: &str = "C2PA_TEST_TSA_HEADERS_CTOR";
        let _guard = EnvVarGuard::set(VAR, "abc123");
        assert_eq!(
            TsaHeader::from_env("Authorization", VAR)
                .with_format("Bearer {value}")
                .resolve()
                .unwrap(),
            ("Authorization".to_owned(), "Bearer abc123".to_owned())
        );
    }

    /// The headers must reach the TSA on the wire, next to the SDK's own
    /// `Content-Type`. The mock answers 500 so the request is observable without
    /// a real RFC 3161 response; the resulting error is a time stamp error from
    /// the HTTP round trip, not a configuration error raised before sending.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_headers_are_sent_with_the_time_stamp_request() {
        use httpmock::MockServer;

        use crate::Error;

        let server = MockServer::start();
        let tsa = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/tsa")
                .header("Authorization", "Bearer abc123")
                .header("X-Tenant", "acme-prod")
                .header("Content-Type", "application/timestamp-query");
            then.status(500);
        });

        let settings = local_signer_settings_with_tsa_headers(
            &server.url("/tsa"),
            serde_json::json!([
                { "name": "Authorization", "value": "Bearer abc123" },
                { "name": "X-Tenant", "value": "acme-prod" },
            ]),
        )
        .unwrap();
        let signer = c2pa_signer_from(settings).unwrap();

        let result = signer
            .send_timestamp_request(b"claim bytes")
            .expect("signer has a tsa_url, so a request is attempted");

        tsa.assert();
        assert!(
            matches!(result, Err(Error::TimeStampError(_))),
            "{result:?}"
        );
    }

    /// The `TimeStamp` assertion refresh path (used by `Builder` for ingredient
    /// manifests) sends the same headers.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn tsa_headers_are_sent_when_refreshing_timestamp_assertions() {
        use httpmock::MockServer;

        let server = MockServer::start();
        let tsa = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/tsa")
                .header("Authorization", "Bearer abc123")
                .header("Content-Type", "application/timestamp-query");
            then.status(500);
        });

        let headers = Some(vec![(
            "Authorization".to_owned(),
            "Bearer abc123".to_owned(),
        )]);
        let result = crate::assertions::TimeStamp::send_timestamp_token_request(
            &server.url("/tsa"),
            headers,
            b"signature",
            &crate::Context::new(),
        );

        tsa.assert();
        assert!(result.is_err());
    }
}
