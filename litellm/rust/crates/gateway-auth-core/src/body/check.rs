//! The request body check. A caller who could set a deployment's endpoint, identity or credentials
//! from the body could send the proxy's own secrets to a host of their choosing, so each of those
//! parameters is refused wherever a body can carry it unless an admin granted it.

use std::{borrow::Cow, cell::OnceCell, collections::BTreeSet};

use super::{
    grant::{MAX_FALLBACK_MODELS, Reachable},
    host::Host,
    names::{
        API_KEY, BUCKET_PARAMS, CREDENTIAL_NAME, FALLBACK_FIELDS, METADATA_KEYS,
        NESTED_CONFIG_KEYS, Names, VERTEX_TARGET_PARAMS, is_content_key, is_metadata_key,
    },
    policy::{Deferred, Policy, allowlist},
    surface::Surface,
    value::{CallerValue, Params},
};
use crate::error::body::{Rejection, ServerOwnedKind};

const USER_CONFIG: &str = "user_config";
const ROUTER_SETTINGS_OVERRIDE: &str = "router_settings_override";
const LITELLM_PARAMS: &str = "litellm_params";

/// One request body and what its route and caller say about it.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub body: &'a Params,
    pub surface: Surface,
    /// The model the request names, empty when it names none.
    pub model: &'a str,
    /// The model the route's path names, on routes that carry one there.
    pub route_model: Option<&'a str>,
    /// Every fallback target the body names, a model name or a mapping of call parameters.
    pub fallback_targets: &'a [CallerValue],
    pub deferred: Deferred,
}

/// Why a body was not accepted: the proxy refuses it, or the host could not answer.
#[derive(Debug, PartialEq)]
pub enum Failure<E> {
    Rejected(Rejection),
    Host(E),
}

impl<E> From<Rejection> for Failure<E> {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}

type Checked<E> = Result<(), Failure<E>>;

pub fn check<H: Host>(
    request: &Request<'_>,
    names: &Names,
    policy: &Policy,
    host: &H,
) -> Checked<H::Error> {
    Check {
        request,
        names,
        policy,
        host,
        reachable: OnceCell::new(),
    }
    .run()
}

/// How one mapping of a body is judged.
#[derive(Clone, Copy)]
struct Rules<'r> {
    overrides: &'r [String],
    /// Whether a secret reference in a parameter a provider resolves is refused here. Metadata
    /// is only logged, so a tag there that looks like one is left alone.
    secret_references: bool,
    token_exchange_allowed: bool,
    owned: &'r [&'r str],
}

struct Check<'a, H: Host> {
    request: &'a Request<'a>,
    names: &'a Names,
    policy: &'a Policy,
    host: &'a H,
    /// Resolved on the first override that only a deployment's opt-in could allow.
    reachable: OnceCell<Option<Reachable>>,
}

impl<H: Host> Check<'_, H> {
    fn run(&self) -> Checked<H::Error> {
        let request = self.request;
        let surface = request.surface;
        if request.body.contains("model_list") {
            return Err(Rejection::ModelList.into());
        }

        let root = if surface.names_vertex_target {
            Cow::Owned(request.body.without(&VERTEX_TARGET_PARAMS))
        } else {
            Cow::Borrowed(request.body)
        };
        self.section(
            &root,
            Rules {
                overrides: self.names.overrides(),
                secret_references: true,
                token_exchange_allowed: surface.manages_mcp_servers,
                owned: surface.owned,
            },
        )?;
        for config in self.nested_configs(request.body)? {
            self.section(&config, self.config_rules())?;
        }
        for key in METADATA_KEYS {
            if let Some(metadata) = self.mapping(request.body.get(key))? {
                self.section(&metadata, self.metadata_rules())?;
            }
            let prefix = format!("{key}[");
            if request.body.keys().any(|name| name.starts_with(&prefix)) {
                let entries = self.host.form_metadata(&prefix).map_err(Failure::Host)?;
                self.section(&entries, self.metadata_rules())?;
            }
        }
        for target in request.fallback_targets {
            match target {
                CallerValue::Map(params) => {
                    self.section(params, self.config_rules())?;
                    if let Some(model) = params.get("model").and_then(CallerValue::text) {
                        self.url_destination(model)?;
                    }
                }
                CallerValue::Text(name) => self.url_destination(name)?,
                CallerValue::Null | CallerValue::List(_) | CallerValue::Other => {}
            }
        }
        self.user_config_federation()?;
        self.litellm_params()?;
        self.user_config_secret_references()?;
        if surface.model_call && !surface.manages_deployments {
            self.unlisted_secret_references()?;
        }
        Ok(())
    }

    fn config_rules(&self) -> Rules<'_> {
        Rules {
            overrides: self.names.overrides(),
            secret_references: true,
            token_exchange_allowed: false,
            owned: &[],
        }
    }

    fn metadata_rules(&self) -> Rules<'_> {
        Rules {
            overrides: self.names.metadata_overrides(),
            secret_references: false,
            token_exchange_allowed: false,
            owned: &[],
        }
    }

    fn section(&self, params: &Params, rules: Rules<'_>) -> Checked<H::Error> {
        let names = self.names;
        self.server_owned(params, |key| {
            rules.token_exchange_allowed && names.is_token_exchange(key)
        })?;
        api_key_oidc_reference(params)?;
        if !self.request.surface.manages_deployments {
            self.federated_credential(params)?;
            if rules.secret_references {
                first_secret_reference(params, |param| names.resolves_secrets(param))?;
            }
        }
        for param in rules.overrides {
            let Some(value) = params.get(param) else {
                continue;
            };
            if rules.owned.contains(&param.as_str()) {
                continue;
            }
            if self.policy.allow_client_side_credentials {
                return Ok(());
            }
            if self.policy.admits(param, value) {
                continue;
            }
            if self.request.deferred.s3_buckets && BUCKET_PARAMS.contains(&param.as_str()) {
                continue;
            }
            if self.request.deferred.model_checks {
                continue;
            }
            if self.granted(param, value)? {
                continue;
            }
            return Err(Rejection::Override {
                param: param.clone(),
                allowlist: allowlist(param),
            }
            .into());
        }
        Ok(())
    }

    /// A federation or token-exchange setting decides whose identity the proxy presents upstream,
    /// so no body sets one, with or without a client-side credential opt-in. A form spells a
    /// repeated field `name[]`.
    fn server_owned(&self, params: &Params, exempt: impl Fn(&str) -> bool) -> Checked<H::Error> {
        let submitted: Vec<&str> = params
            .keys()
            .filter(|key| !exempt(key))
            .map(|key| key.strip_suffix("[]").unwrap_or(key))
            .collect();
        let found = self
            .names
            .federation()
            .iter()
            .find(|param| submitted.contains(&param.as_str()));
        match found {
            Some(param) => Err(Rejection::ServerOwned {
                param: param.clone(),
                kind: if self.names.is_github_copilot(param) {
                    ServerOwnedKind::GitHubCopilot
                } else {
                    ServerOwnedKind::Federation
                },
            }
            .into()),
            None => Ok(()),
        }
    }

    /// Naming a stored credential merges its values into the call, so a body naming a federated
    /// one picks a server-owned identity exactly as sending the federation fields inline would.
    fn federated_credential(&self, params: &Params) -> Checked<H::Error> {
        let Some(named) = credential_name(params) else {
            return Ok(());
        };
        let values = self.host.credential(named).map_err(Failure::Host)?;
        let field = self
            .names
            .federation()
            .iter()
            .map(String::as_str)
            .find(|name| values.get(name).is_some_and(|value| !value.is_null()))
            .or_else(|| holds_api_key_oidc_reference(&values).then_some(API_KEY));
        match field {
            Some(field) => Err(Rejection::FederatedCredential {
                named: named.to_owned(),
                field: field.to_owned(),
            }
            .into()),
            None => Ok(()),
        }
    }

    fn api_key_reference(&self, params: &Params) -> Checked<H::Error> {
        api_key_oidc_reference(params)?;
        let Some(named) = credential_name(params) else {
            return Ok(());
        };
        let values = self.host.credential(named).map_err(Failure::Host)?;
        if holds_api_key_oidc_reference(&values) {
            return Err(Rejection::CredentialApiKeyOidcReference {
                named: named.to_owned(),
            }
            .into());
        }
        Ok(())
    }

    fn granted(&self, param: &str, value: &CallerValue) -> Result<bool, Failure<H::Error>> {
        match (self.reachable()?, self.host.deployments()) {
            (Some(reachable), Some(router)) => reachable
                .grants(router, param, value)
                .map_err(Failure::Host),
            _ => Ok(false),
        }
    }

    fn reachable(&self) -> Result<Option<&Reachable>, Failure<H::Error>> {
        if let Some(resolved) = self.reachable.get() {
            return Ok(resolved.as_ref());
        }
        let request = self.request;
        let also_requested: BTreeSet<String> = request
            .fallback_targets
            .iter()
            .filter_map(fallback_model)
            .chain(request.route_model.filter(|model| !model.is_empty()))
            .map(str::to_owned)
            .collect();
        if also_requested.len() > MAX_FALLBACK_MODELS {
            return Err(Rejection::TooManyFallbackModels {
                limit: MAX_FALLBACK_MODELS,
            }
            .into());
        }
        let resolved = match self.host.deployments() {
            Some(router) => {
                let model = if request.model.is_empty() {
                    request.route_model.unwrap_or_default()
                } else {
                    request.model
                };
                let requested: BTreeSet<String> = also_requested
                    .into_iter()
                    .chain([model.to_owned()])
                    .collect();
                Some(Reachable::resolve(router, &requested).map_err(Failure::Host)?)
            }
            None => None,
        };
        Ok(self.reachable.get_or_init(|| resolved).as_ref())
    }

    fn url_destination(&self, value: &str) -> Checked<H::Error> {
        if self
            .host
            .url_destination_allowed(value)
            .map_err(Failure::Host)?
        {
            return Ok(());
        }
        Err(Rejection::UrlFallbackDestination {
            value: value.to_owned(),
        }
        .into())
    }

    /// A caller-supplied router config builds its deployments from the body, so its
    /// `litellm_params` are held to the federation rules a configured deployment's are not.
    fn user_config_federation(&self) -> Checked<H::Error> {
        let Some(config) = self.mapping(self.request.body.get(USER_CONFIG))? else {
            return Ok(());
        };
        let defaults = self.mapping(config.get("default_litellm_params"))?;
        let mut all: Vec<Cow<'_, Params>> = defaults.into_iter().collect();
        let deployments = config
            .get("model_list")
            .and_then(CallerValue::list)
            .unwrap_or_default();
        for deployment in deployments.iter().filter_map(CallerValue::map) {
            all.extend(self.mapping(deployment.get("litellm_params"))?);
        }
        for params in &all {
            self.server_owned(params, |_| false)?;
            api_key_oidc_reference(params)?;
            if !self.request.surface.manages_deployments {
                self.federated_credential(params)?;
            }
        }
        Ok(())
    }

    fn litellm_params(&self) -> Checked<H::Error> {
        let Some(params) = self.mapping(self.request.body.get(LITELLM_PARAMS))? else {
            return Ok(());
        };
        if self.request.surface.manages_deployments {
            self.server_owned(&params, |key| key == "chatgpt_auth_file")?;
        } else {
            self.server_owned(&params, |_| false)?;
            api_key_oidc_reference(&params)?;
            self.federated_credential(&params)?;
        }
        for config in self.nested_configs(&params)? {
            self.api_key_reference(&config)?;
        }
        if let Some(metadata) = self.mapping(params.get("metadata"))? {
            self.section(&metadata, self.metadata_rules())?;
        }
        Ok(())
    }

    /// The router resolves every field of a caller-supplied deployment the way it resolves a
    /// configured one, so a reference in any of them reads a proxy secret for the caller.
    fn user_config_secret_references(&self) -> Checked<H::Error> {
        let Some(config) = self.mapping(self.request.body.get(USER_CONFIG))? else {
            return Ok(());
        };
        let mut all = Vec::new();
        for key in ["model_list", "search_tools"] {
            for entry in self.mappings_in(config.get(key))? {
                all.extend(
                    self.mapping(entry.get("litellm_params"))?
                        .map(Cow::into_owned),
                );
            }
        }
        all.extend(
            self.mapping(config.get("default_litellm_params"))?
                .map(Cow::into_owned),
        );
        for params in &all {
            self.api_key_reference(params)?;
            first_secret_reference(params, |_| true)?;
            for config in self.nested_configs(params)? {
                first_secret_reference(&config, |_| true)?;
            }
            for source in self.mappings_in(params.get("dataSources"))? {
                if let Some(parameters) = self.mapping(source.get("parameters"))? {
                    first_secret_reference(&parameters, |_| true)?;
                }
            }
        }
        Ok(())
    }

    /// Every key of a model call outside its content can reach a provider as a parameter, and
    /// providers resolve references in more parameters than any list names. So a reference
    /// anywhere a parameter can sit is refused, listed or not.
    fn unlisted_secret_references(&self) -> Checked<H::Error> {
        let request = self.request;
        for (key, value) in request.body.iter() {
            if is_content_key(key)
                || is_metadata_key(key)
                || NESTED_CONFIG_KEYS.contains(&key)
                || FALLBACK_FIELDS.contains(&key)
                || key == USER_CONFIG
            {
                continue;
            }
            let holds = match (key, value.map()) {
                (ROUTER_SETTINGS_OVERRIDE, Some(settings)) => {
                    holds_outside(settings, |name| FALLBACK_FIELDS.contains(&name))
                }
                (LITELLM_PARAMS, Some(params)) => holds_outside(params, is_metadata_key),
                _ => value.holds_secret_reference(),
            };
            if holds {
                return Err(secret_reference(key).into());
            }
        }
        for config in self.nested_configs(request.body)? {
            first_holding_secret_reference(&config)?;
        }
        for target in request.fallback_targets.iter().filter_map(CallerValue::map) {
            first_holding_secret_reference(target)?;
        }
        // A caller-supplied router resolves references in its own settings, not only in its
        // deployments.
        if let Some(config) = self.mapping(request.body.get(USER_CONFIG))? {
            first_holding_secret_reference(&config)?;
        }
        Ok(())
    }

    fn nested_configs<'v>(
        &self,
        params: &'v Params,
    ) -> Result<Vec<Cow<'v, Params>>, Failure<H::Error>> {
        let mut configs = Vec::new();
        for key in NESTED_CONFIG_KEYS {
            configs.extend(self.mapping(params.get(key))?);
        }
        Ok(configs)
    }

    fn mappings_in<'v>(
        &self,
        value: Option<&'v CallerValue>,
    ) -> Result<Vec<Cow<'v, Params>>, Failure<H::Error>> {
        let mut mappings = Vec::new();
        for entry in value.and_then(CallerValue::list).unwrap_or_default() {
            mappings.extend(self.mapping(Some(entry))?);
        }
        Ok(mappings)
    }

    /// A mapping, or the one a JSON string decodes to, since forms and `extra_body` carry
    /// metadata and configs as text the proxy decodes after this check.
    fn mapping<'v>(
        &self,
        value: Option<&'v CallerValue>,
    ) -> Result<Option<Cow<'v, Params>>, Failure<H::Error>> {
        match value {
            Some(CallerValue::Map(params)) => Ok(Some(Cow::Borrowed(params))),
            Some(CallerValue::Text(text)) => Ok(self
                .host
                .decode(text)
                .map_err(Failure::Host)?
                .map(Cow::Owned)),
            Some(CallerValue::Null | CallerValue::List(_) | CallerValue::Other) | None => Ok(None),
        }
    }
}

fn credential_name(params: &Params) -> Option<&str> {
    params
        .get(CREDENTIAL_NAME)
        .and_then(CallerValue::text)
        .filter(|named| !named.is_empty())
}

fn holds_api_key_oidc_reference(params: &Params) -> bool {
    params
        .get(API_KEY)
        .is_some_and(CallerValue::is_oidc_reference)
}

fn api_key_oidc_reference(params: &Params) -> Result<(), Rejection> {
    if holds_api_key_oidc_reference(params) {
        return Err(Rejection::ApiKeyOidcReference);
    }
    Ok(())
}

fn secret_reference(param: &str) -> Rejection {
    Rejection::SecretReference {
        param: param.to_owned(),
    }
}

fn first_secret_reference(params: &Params, reads: impl Fn(&str) -> bool) -> Result<(), Rejection> {
    match params
        .iter()
        .find(|(param, value)| reads(param) && value.is_secret_reference())
    {
        Some((param, _)) => Err(secret_reference(param)),
        None => Ok(()),
    }
}

fn first_holding_secret_reference(params: &Params) -> Result<(), Rejection> {
    match params
        .iter()
        .find(|(_, value)| value.holds_secret_reference())
    {
        Some((param, _)) => Err(secret_reference(param)),
        None => Ok(()),
    }
}

/// Whether a reference sits below any entry `skipped` does not name.
fn holds_outside(params: &Params, skipped: impl Fn(&str) -> bool) -> bool {
    params
        .iter()
        .any(|(name, value)| !skipped(name) && value.holds_secret_reference())
}

fn fallback_model(target: &CallerValue) -> Option<&str> {
    match target {
        CallerValue::Text(name) => Some(name),
        CallerValue::Map(params) => params.get("model").and_then(CallerValue::text),
        CallerValue::Null | CallerValue::List(_) | CallerValue::Other => None,
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rstest::{fixture, rstest};
    use serde_json::{Value, json};

    use super::{
        super::{
            host::{Deployment, Deployments, OptIn},
            names::HostTables,
        },
        *,
    };
    use crate::error::body::Allowlist;

    const CHAT: &str = "/v1/chat/completions";

    fn value(json: &Value) -> CallerValue {
        match json {
            Value::Null => CallerValue::Null,
            Value::String(text) => CallerValue::Text(text.clone()),
            Value::Array(items) => CallerValue::List(items.iter().map(value).collect()),
            Value::Object(_) => CallerValue::Map(params(json)),
            Value::Bool(_) | Value::Number(_) => CallerValue::Other,
        }
    }

    fn params(json: &Value) -> Params {
        json.as_object()
            .into_iter()
            .flatten()
            .map(|(key, entry)| (key.clone(), value(entry)))
            .collect()
    }

    /// One group, `azure-group`, whose only deployment opts in to `opt_in`.
    struct Router {
        opt_in: Vec<&'static str>,
    }

    impl Deployments for Router {
        type Error = Infallible;

        fn group(&self, model: &str) -> Result<Vec<Deployment>, Infallible> {
            Ok((model == "azure-group")
                .then(|| Deployment {
                    model_name: "azure-group".to_owned(),
                    provider: Some("azure".to_owned()),
                    opt_in: Some(OptIn {
                        params: self
                            .opt_in
                            .iter()
                            .map(|param| (*param).to_owned())
                            .collect(),
                        api_base_patterns: Vec::new(),
                    }),
                })
                .into_iter()
                .collect())
        }

        fn alias(&self, _name: &str) -> Result<Option<String>, Infallible> {
            Ok(None)
        }

        fn fallbacks(&self, _name: &str) -> Result<Vec<String>, Infallible> {
            Ok(Vec::new())
        }

        fn api_base_matches(&self, pattern: &str, value: &str) -> Result<bool, Infallible> {
            Ok(pattern == value)
        }
    }

    #[derive(Default)]
    struct Proxy {
        router: Option<Router>,
        /// A stored credential named `federated`.
        federated_credential: Value,
        form_metadata: Value,
    }

    impl Host for Proxy {
        type Error = Infallible;
        type Deployments = Router;

        fn decode(&self, text: &str) -> Result<Option<Params>, Infallible> {
            Ok(serde_json::from_str::<Value>(text)
                .ok()
                .filter(Value::is_object)
                .map(|json| params(&json)))
        }

        fn form_metadata(&self, _prefix: &str) -> Result<Params, Infallible> {
            Ok(params(&self.form_metadata))
        }

        fn credential(&self, name: &str) -> Result<Params, Infallible> {
            Ok(if name == "federated" {
                params(&self.federated_credential)
            } else {
                Params::default()
            })
        }

        fn url_destination_allowed(&self, value: &str) -> Result<bool, Infallible> {
            Ok(!value.contains("attacker.example"))
        }

        fn deployments(&self) -> Option<&Router> {
            self.router.as_ref()
        }
    }

    #[fixture]
    fn names() -> Names {
        let owned = |names: &[&str]| names.iter().map(|name| (*name).to_owned()).collect();
        Names::new(HostTables {
            callback_params: owned(&["langfuse_host"]),
            blocked_callback_params: Vec::new(),
            pricing_params: owned(&["input_cost_per_token"]),
            federation_params: owned(&[
                "anthropic_issuer_url",
                "token_exchange_endpoint",
                "github_copilot_app_id",
                "chatgpt_auth_file",
            ]),
            token_exchange_params: owned(&["token_exchange_endpoint"]),
            github_copilot_params: owned(&["github_copilot_app_id"]),
            upstream_bound_params: owned(&["api_key", "aws_access_key_id", "organization"]),
        })
    }

    struct Case<'a> {
        route: Option<&'a str>,
        route_model: Option<&'a str>,
        body: Value,
        fallback_targets: Value,
        policy: Policy,
        deferred: Deferred,
        proxy: Proxy,
    }

    impl Case<'_> {
        fn new(body: Value) -> Self {
            Self {
                route: Some(CHAT),
                route_model: None,
                body,
                fallback_targets: json!([]),
                policy: Policy::default(),
                deferred: Deferred::default(),
                proxy: Proxy::default(),
            }
        }

        fn run(&self, names: &Names) -> Result<(), Rejection> {
            let body = params(&self.body);
            let fallback_targets: Vec<CallerValue> = self
                .fallback_targets
                .as_array()
                .into_iter()
                .flatten()
                .map(value)
                .collect();
            let request = Request {
                body: &body,
                surface: Surface::of(self.route),
                model: self.body["model"].as_str().unwrap_or_default(),
                route_model: self.route_model,
                fallback_targets: &fallback_targets,
                deferred: self.deferred,
            };
            match check(&request, names, &self.policy, &self.proxy) {
                Ok(()) => Ok(()),
                Err(Failure::Rejected(rejection)) => Err(rejection),
            }
        }
    }

    fn on(route: &'static str, body: Value) -> Case<'static> {
        Case {
            route: Some(route),
            ..Case::new(body)
        }
    }

    fn open(body: Value) -> Case<'static> {
        Case {
            policy: Policy {
                allow_client_side_credentials: true,
                ..Policy::default()
            },
            ..Case::new(body)
        }
    }

    fn routed(opt_in: &[&'static str], body: Value) -> Case<'static> {
        Case {
            proxy: Proxy {
                router: Some(Router {
                    opt_in: opt_in.to_vec(),
                }),
                ..Proxy::default()
            },
            ..Case::new(body)
        }
    }

    fn refused(param: &str) -> Result<(), Rejection> {
        Err(Rejection::Override {
            param: param.to_owned(),
            allowlist: Allowlist::None,
        })
    }

    fn reference(param: &str) -> Result<(), Rejection> {
        Err(secret_reference(param))
    }

    #[rstest]
    #[case::endpoint(json!({"model": "gpt-4o", "api_base": "https://attacker.example"}), "api_base")]
    #[case::endpoint_beside_the_callers_own_key(
        json!({"model": "gpt-4o", "api_key": "sk-own", "api_base": "https://attacker.example"}),
        "api_base"
    )]
    #[case::entra_credential(json!({"model": "gpt-4o", "client_id": "caller"}), "client_id")]
    #[case::callback_destination(json!({"model": "gpt-4o", "langfuse_host": "https://attacker.example"}), "langfuse_host")]
    #[case::pricing(json!({"model": "gpt-4o", "input_cost_per_token": 0}), "input_cost_per_token")]
    #[case::in_extra_body(json!({"model": "gpt-4o", "extra_body": {"api_base": "https://attacker.example"}}), "api_base")]
    #[case::in_an_embedding_config(
        json!({"model": "gpt-4o", "litellm_embedding_config": {"api_base": "https://attacker.example"}}),
        "api_base"
    )]
    #[case::in_extra_body_sent_as_text(
        json!({"model": "gpt-4o", "extra_body": "{\"azure_ad_token\": \"caller\"}"}),
        "azure_ad_token"
    )]
    #[case::in_metadata(json!({"model": "gpt-4o", "metadata": {"langfuse_host": "https://attacker.example"}}), "langfuse_host")]
    #[case::in_metadata_sent_as_text(
        json!({"model": "gpt-4o", "litellm_metadata": "{\"langfuse_host\": \"https://attacker.example\"}"}),
        "langfuse_host"
    )]
    #[case::in_litellm_params_metadata(
        json!({"model": "gpt-4o", "litellm_params": {"metadata": {"langfuse_host": "https://attacker.example"}}}),
        "langfuse_host"
    )]
    fn an_override_is_refused_wherever_a_body_carries_it(
        names: Names,
        #[case] body: Value,
        #[case] param: &str,
    ) {
        assert_eq!(Case::new(body).run(&names), refused(param));
    }

    #[rstest]
    fn a_form_spelled_metadata_entry_is_judged_as_metadata(names: Names) {
        let case = Case {
            proxy: Proxy {
                form_metadata: json!({"langfuse_host": "https://attacker.example"}),
                ..Proxy::default()
            },
            ..Case::new(
                json!({"model": "whisper-1", "metadata[langfuse_host]": "https://attacker.example"}),
            )
        };

        assert_eq!(case.run(&names), refused("langfuse_host"));
    }

    #[rstest]
    #[case::dict_target(json!([{"model": "gpt-4o", "api_base": "https://attacker.example"}]), refused("api_base"))]
    #[case::url_valued_name(
        json!(["https://attacker.example/v1"]),
        Err(Rejection::UrlFallbackDestination { value: "https://attacker.example/v1".to_owned() })
    )]
    #[case::url_valued_dict_model(
        json!([{"model": "https://attacker.example/v1"}]),
        Err(Rejection::UrlFallbackDestination { value: "https://attacker.example/v1".to_owned() })
    )]
    #[case::model_names(json!(["gpt-4o-mini", {"model": "gpt-4o"}]), Ok(()))]
    fn a_fallback_target_is_held_to_the_rules_of_the_request(
        names: Names,
        #[case] fallback_targets: Value,
        #[case] expected: Result<(), Rejection>,
    ) {
        let case = Case {
            fallback_targets,
            ..Case::new(json!({"model": "gpt-4o"}))
        };

        assert_eq!(case.run(&names), expected);
    }

    #[rstest]
    fn a_body_never_carries_a_model_list(names: Names) {
        let case = open(json!({"model": "gpt-4o", "model_list": []}));

        assert_eq!(case.run(&names), Err(Rejection::ModelList));
    }

    #[rstest]
    #[case::proxy_wide(open(json!({"model": "gpt-4o", "api_base": "https://own.example", "langfuse_host": "h"})))]
    #[case::deployment_opt_in(routed(&["client_id"], json!({"model": "azure-group", "client_id": "caller"})))]
    #[case::listed_bucket(Case {
        policy: Policy { s3_buckets: vec!["team-bucket".to_owned()], ..Policy::default() },
        ..Case::new(json!({"model": "gpt-4o", "s3_bucket_name": "team-bucket"}))
    })]
    #[case::listed_endpoint_url(Case {
        policy: Policy { s3_endpoint_urls: vec!["https://s3.own.example".to_owned()], ..Policy::default() },
        ..Case::new(json!({"model": "gpt-4o", "s3_endpoint_url": "https://s3.own.example"}))
    })]
    #[case::bucket_left_to_the_handler(Case {
        deferred: Deferred { s3_buckets: true, ..Deferred::default() },
        ..Case::new(json!({"model": "gpt-4o", "s3_output_bucket_name": "any"}))
    })]
    #[case::model_check_left_until_the_team_is_known(Case {
        deferred: Deferred { model_checks: true, ..Deferred::default() },
        ..Case::new(json!({"model": "gpt-4o", "api_base": "https://own.example"}))
    })]
    fn an_admins_grant_lets_an_override_through(names: Names, #[case] case: Case<'static>) {
        assert_eq!(case.run(&names), Ok(()));
    }

    #[rstest]
    #[case::another_param(routed(&["client_id"], json!({"model": "azure-group", "client_id": "caller", "client_secret": "s"})), "client_secret")]
    #[case::another_group(routed(&["client_id"], json!({"model": "other-group", "client_id": "caller"})), "client_id")]
    #[case::no_router(Case::new(json!({"model": "azure-group", "client_id": "caller"})), "client_id")]
    fn a_deployment_opt_in_covers_only_its_own_group_and_param(
        names: Names,
        #[case] case: Case<'static>,
        #[case] param: &str,
    ) {
        assert_eq!(case.run(&names), refused(param));
    }

    #[rstest]
    #[case::unlisted_bucket(
        Policy { s3_buckets: vec!["team-bucket".to_owned()], ..Policy::default() },
        "s3_bucket_name",
        Allowlist::Buckets
    )]
    #[case::unlisted_endpoint_url(Policy::default(), "s3_endpoint_url", Allowlist::EndpointUrls)]
    fn a_storage_override_outside_its_allowlist_is_refused_naming_the_setting(
        names: Names,
        #[case] policy: Policy,
        #[case] param: &str,
        #[case] allowlist: Allowlist,
    ) {
        let case = Case {
            policy,
            ..Case::new(json!({"model": "gpt-4o", param: "other"}))
        };

        assert_eq!(
            case.run(&names),
            Err(Rejection::Override {
                param: param.to_owned(),
                allowlist
            })
        );
    }

    #[rstest]
    #[case::entra_credential(open(json!({"model": "azure-group", "client_id": "os.environ/LITELLM_MASTER_KEY", "tenant_id": "t"})), "client_id")]
    #[case::oidc(open(json!({"model": "azure-group", "azure_ad_token": "oidc/env/LITELLM_MASTER_KEY"})), "azure_ad_token")]
    #[case::upstream_bound(open(json!({"model": "azure-group", "aws_access_key_id": "os.environ/LITELLM_MASTER_KEY"})), "aws_access_key_id")]
    #[case::in_extra_body(open(json!({"model": "azure-group", "extra_body": {"client_secret": "os.environ/LITELLM_MASTER_KEY"}})), "client_secret")]
    #[case::deployment_opted_in(
        routed(&["client_id"], json!({"model": "azure-group", "client_id": "os.environ/LITELLM_MASTER_KEY"})),
        "client_id"
    )]
    fn no_grant_lets_a_caller_have_a_secret_reference_resolved(
        names: Names,
        #[case] case: Case<'static>,
        #[case] param: &str,
    ) {
        assert_eq!(case.run(&names), reference(param));
    }

    #[rstest]
    #[case::root(json!({"model": "gpt-4o", "api_key": "oidc/google/aud"}))]
    #[case::extra_body(json!({"model": "gpt-4o", "extra_body": {"api_key": "oidc/google/aud"}}))]
    #[case::litellm_params_extra_body(json!({"model": "gpt-4o", "litellm_params": {"extra_body": {"api_key": "oidc/google/aud"}}}))]
    fn an_oidc_api_key_is_refused_as_the_proxys_own_identity(names: Names, #[case] body: Value) {
        assert_eq!(open(body).run(&names), Err(Rejection::ApiKeyOidcReference));
    }

    #[rstest]
    #[case::unlisted_param(json!({"model": "gpt-4o", "some_provider_param": "os.environ/LITELLM_MASTER_KEY"}), "some_provider_param")]
    #[case::below_an_unlisted_param(
        json!({"model": "gpt-4o", "provider_options": {"auth": ["plain", {"token": "oidc/env/LITELLM_MASTER_KEY"}]}}),
        "provider_options"
    )]
    #[case::unlisted_param_in_extra_body(json!({"model": "gpt-4o", "extra_body": {"some_provider_param": "os.environ/HOME"}}), "some_provider_param")]
    #[case::below_litellm_params(json!({"model": "gpt-4o", "litellm_params": {"anything": "os.environ/HOME"}}), "litellm_params")]
    #[case::below_router_settings(json!({"model": "gpt-4o", "router_settings_override": {"timeout": "os.environ/HOME"}}), "router_settings_override")]
    fn a_model_call_carries_no_secret_reference_outside_its_content(
        names: Names,
        #[case] body: Value,
        #[case] param: &str,
    ) {
        assert_eq!(open(body).run(&names), reference(param));
    }

    #[rstest]
    #[case::connection_setting(json!({"redis_password": "os.environ/LITELLM_MASTER_KEY"}), "redis_password")]
    #[case::below_a_setting(json!({"cache_kwargs": {"password": "oidc/env/LITELLM_MASTER_KEY"}}), "cache_kwargs")]
    #[case::beside_a_deployment(
        json!({
            "model_list": [{"litellm_params": {"model": "openai/gpt-4o", "api_key": "sk-own"}}],
            "redis_url": "os.environ/LITELLM_MASTER_KEY",
        }),
        "redis_url"
    )]
    #[case::sent_as_text(json!("{\"redis_password\": \"os.environ/LITELLM_MASTER_KEY\"}"), "redis_password")]
    fn a_caller_supplied_router_carries_no_secret_reference_in_any_setting(
        names: Names,
        #[case] user_config: Value,
        #[case] param: &str,
    ) {
        let case = open(json!({"model": "caller-model", "user_config": user_config}));

        assert_eq!(case.run(&names), reference(param));
    }

    #[rstest]
    fn a_caller_supplied_router_may_carry_the_callers_own_settings(names: Names) {
        let case = open(json!({
            "model": "caller-model",
            "user_config": {
                "model_list": [{"litellm_params": {"model": "openai/gpt-4o", "api_key": "sk-own"}}],
                "redis_host": "cache.own.example",
                "redis_password": "own-password",
            },
        }));

        assert_eq!(case.run(&names), Ok(()));
    }

    #[rstest]
    fn a_fallback_target_carries_no_secret_reference_in_any_param(names: Names) {
        let case = Case {
            fallback_targets: json!([{"model": "gpt-4o", "some_provider_param": "os.environ/HOME"}]),
            ..open(json!({"model": "gpt-4o"}))
        };

        assert_eq!(case.run(&names), reference("some_provider_param"));
    }

    #[rstest]
    #[case::prompt(open(json!({"model": "gpt-4o", "prompt": "os.environ/PATH is what in Python?"})))]
    #[case::message(open(json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "os.environ/HOME"}]})))]
    #[case::tool_schema(open(json!({"model": "gpt-4o", "tools": [{"function": {"parameters": {"default": "os.environ/OPENAI_API_KEY"}}}]})))]
    #[case::metadata_tag(open(json!({"model": "gpt-4o", "metadata": {"client_id": "os.environ/HOME", "note": "oidc/azure/team-a"}})))]
    #[case::litellm_params_metadata_tag(open(json!({"model": "gpt-4o", "litellm_params": {"metadata": {"note": "os.environ/HOME"}}})))]
    #[case::mentioned_later(open(json!({"model": "gpt-4o", "client_id": "read os.environ/HOME"})))]
    #[case::mentioned_later_in_an_unlisted_param(open(json!({"model": "gpt-4o", "some_provider_param": "read os.environ/HOME"})))]
    #[case::callers_own_key(open(json!({"model": "gpt-4o", "api_key": "sk-caller-own-key"})))]
    #[case::fallback_model_name(open(json!({"model": "gpt-4o", "fallbacks": ["os.environ/HOME"]})))]
    #[case::fallback_model_name_in_router_settings(
        open(json!({"model": "gpt-4o", "router_settings_override": {"fallbacks": [{"gpt-4o": ["os.environ/HOME"]}]}}))
    )]
    #[case::key_management_route(on("/key/generate", json!({"key_alias": "os.environ/HOME"})))]
    #[case::credential_route(on("/credentials", json!({"credential_values": {"api_key": "os.environ/AZURE_API_KEY"}})))]
    fn text_that_no_provider_resolves_may_look_like_a_secret_reference(
        names: Names,
        #[case] case: Case<'static>,
    ) {
        assert_eq!(case.run(&names), Ok(()));
    }

    #[rstest]
    #[case::deployment_secret_reference(on("/model/new", json!({"model_name": "azure-group", "api_key": "os.environ/AZURE_API_KEY"})), Ok(()))]
    #[case::deployment_update_by_id(on("/model/abc/update", json!({"litellm_params": {"api_key": "os.environ/AZURE_API_KEY"}})), Ok(()))]
    #[case::transcription_session_secret(on("/v1/realtime/transcription_sessions", json!({"client_secret": {"expires_after": {}}})), Ok(()))]
    #[case::transcription_session_other_entra(on("/v1/realtime/transcription_sessions", json!({"client_id": "caller"})), refused("client_id"))]
    #[case::mcp_oauth_client(on("/v1/mcp/server", json!({"client_id": "id", "client_secret": "secret"})), Ok(()))]
    #[case::mcp_token_exchange(on("/v1/mcp/server", json!({"token_exchange_endpoint": "https://idp.example/token"})), Ok(()))]
    #[case::mcp_other_entra(on("/v1/mcp/server", json!({"tenant_id": "t"})), refused("tenant_id"))]
    #[case::mcp_other_federation(
        on("/v1/mcp/server", json!({"anthropic_issuer_url": "https://idp.example"})),
        Err(Rejection::ServerOwned { param: "anthropic_issuer_url".to_owned(), kind: ServerOwnedKind::Federation })
    )]
    #[case::deployment_chatgpt_auth_file(on("/model/new", json!({"litellm_params": {"chatgpt_auth_file": "auth.json"}})), Ok(()))]
    #[case::deployment_other_federation(
        on("/model/new", json!({"litellm_params": {"anthropic_issuer_url": "https://idp.example"}})),
        Err(Rejection::ServerOwned { param: "anthropic_issuer_url".to_owned(), kind: ServerOwnedKind::Federation })
    )]
    #[case::introspection_client(on("/introspect", json!({"client_id": "id", "client_secret": "secret"})), Ok(()))]
    #[case::introspection_secret_reference(on("/introspect", json!({"client_id": "os.environ/LITELLM_MASTER_KEY"})), reference("client_id"))]
    #[case::pass_through_entra(on("/azure/openai/deployments/d/chat/completions", json!({"client_id": "caller"})), refused("client_id"))]
    #[case::pass_through_tenant(on("/vertex_ai/v1/projects/p", json!({"tenant_id": "t"})), refused("tenant_id"))]
    #[case::vertex_live_target(on("/vertex_ai/live", json!({"vertex_project": "p", "vertex_location": "l"})), Ok(()))]
    #[case::vertex_live_other_override(on("/vertex_ai/live", json!({"vertex_project": "p", "api_base": "https://attacker.example"})), refused("api_base"))]
    fn a_route_decides_which_names_are_its_own_fields(
        names: Names,
        #[case] case: Case<'static>,
        #[case] expected: Result<(), Rejection>,
    ) {
        assert_eq!(case.run(&names), expected);
    }

    #[rstest]
    #[case::root(json!({"model": "gpt-4o", "anthropic_issuer_url": "https://idp.example"}), "anthropic_issuer_url", ServerOwnedKind::Federation)]
    #[case::form_list_spelling(json!({"model": "gpt-4o", "anthropic_issuer_url[]": "https://idp.example"}), "anthropic_issuer_url", ServerOwnedKind::Federation)]
    #[case::token_exchange_outside_mcp(json!({"model": "gpt-4o", "token_exchange_endpoint": "https://idp.example"}), "token_exchange_endpoint", ServerOwnedKind::Federation)]
    #[case::github_copilot(json!({"model": "gpt-4o", "github_copilot_app_id": 1}), "github_copilot_app_id", ServerOwnedKind::GitHubCopilot)]
    #[case::in_litellm_params(json!({"model": "gpt-4o", "litellm_params": {"anthropic_issuer_url": "https://idp.example"}}), "anthropic_issuer_url", ServerOwnedKind::Federation)]
    #[case::in_a_user_config_deployment(
        json!({"model": "m", "user_config": {"model_list": [{"litellm_params": {"anthropic_issuer_url": "https://idp.example"}}]}}),
        "anthropic_issuer_url",
        ServerOwnedKind::Federation
    )]
    fn a_federation_setting_is_refused_despite_a_proxy_wide_opt_in(
        names: Names,
        #[case] body: Value,
        #[case] param: &str,
        #[case] kind: ServerOwnedKind,
    ) {
        assert_eq!(
            open(body).run(&names),
            Err(Rejection::ServerOwned {
                param: param.to_owned(),
                kind
            })
        );
    }

    #[rstest]
    #[case::federation_field(json!({"anthropic_issuer_url": "https://idp.example"}), "anthropic_issuer_url")]
    #[case::oidc_api_key(json!({"api_key": "oidc/google/aud"}), "api_key")]
    fn a_body_cannot_name_a_federated_credential(
        names: Names,
        #[case] federated_credential: Value,
        #[case] field: &str,
    ) {
        let case = Case {
            proxy: Proxy {
                federated_credential,
                ..Proxy::default()
            },
            ..open(json!({"model": "gpt-4o", "litellm_credential_name": "federated"}))
        };

        assert_eq!(
            case.run(&names),
            Err(Rejection::FederatedCredential {
                named: "federated".to_owned(),
                field: field.to_owned()
            })
        );
    }

    #[rstest]
    fn a_caller_supplied_deployment_cannot_name_a_federated_credential(names: Names) {
        let case = Case {
            proxy: Proxy {
                federated_credential: json!({"anthropic_issuer_url": "https://idp.example"}),
                ..Proxy::default()
            },
            ..open(json!({
                "model": "caller-model",
                "user_config": {"model_list": [{"litellm_params": {"litellm_credential_name": "federated"}}]},
            }))
        };

        assert_eq!(
            case.run(&names),
            Err(Rejection::FederatedCredential {
                named: "federated".to_owned(),
                field: "anthropic_issuer_url".to_owned()
            })
        );
    }

    #[rstest]
    fn a_body_may_name_a_credential_that_holds_plain_values(names: Names) {
        let case = Case {
            proxy: Proxy {
                federated_credential: json!({"api_key": "sk-stored", "anthropic_issuer_url": null}),
                ..Proxy::default()
            },
            ..open(json!({"model": "gpt-4o", "litellm_credential_name": "federated"}))
        };

        assert_eq!(case.run(&names), Ok(()));
    }

    #[rstest]
    #[case::listed_field(json!({"model_list": [{"litellm_params": {"model": "openai/gpt-4o", "api_key": "os.environ/LITELLM_MASTER_KEY"}}]}), "api_key")]
    #[case::unlisted_field(json!({"model_list": [{"litellm_params": {"model": "openai/gpt-4o", "anything": "os.environ/LITELLM_MASTER_KEY"}}]}), "anything")]
    #[case::defaults(json!({"default_litellm_params": {"organization": "os.environ/LITELLM_MASTER_KEY"}}), "organization")]
    #[case::search_tool(json!({"search_tools": [{"litellm_params": {"api_key": "os.environ/LITELLM_MASTER_KEY"}}]}), "api_key")]
    #[case::nested_config(json!({"model_list": [{"litellm_params": {"extra_body": {"token": "os.environ/LITELLM_MASTER_KEY"}}}]}), "token")]
    #[case::data_source(json!({"model_list": [{"litellm_params": {"dataSources": [{"parameters": {"key": "os.environ/LITELLM_MASTER_KEY"}}]}}]}), "key")]
    #[case::entry_sent_as_text(json!({"model_list": ["{\"litellm_params\": {\"api_key\": \"os.environ/LITELLM_MASTER_KEY\"}}"]}), "api_key")]
    fn every_field_of_a_caller_supplied_deployment_is_checked_for_a_reference(
        names: Names,
        #[case] user_config: Value,
        #[case] param: &str,
    ) {
        let case = open(json!({"model": "caller-model", "user_config": user_config}));

        assert_eq!(case.run(&names), reference(param));
    }

    #[rstest]
    fn a_caller_supplied_deployment_may_carry_the_callers_own_credentials(names: Names) {
        let case = open(json!({
            "model": "caller-model",
            "user_config": {"model_list": [{"litellm_params": {
                "model": "openai/gpt-4o", "api_base": "https://own.example", "api_key": "sk-own"
            }}]},
        }));

        assert_eq!(case.run(&names), Ok(()));
    }

    #[rstest]
    #[case::at_the_limit(MAX_FALLBACK_MODELS, refused("api_base"))]
    #[case::past_the_limit(
        MAX_FALLBACK_MODELS + 1,
        Err(Rejection::TooManyFallbackModels { limit: MAX_FALLBACK_MODELS })
    )]
    fn fallback_models_are_checked_up_to_the_limit_and_refused_past_it(
        names: Names,
        #[case] count: usize,
        #[case] expected: Result<(), Rejection>,
    ) {
        let models: Vec<String> = (0..count).map(|index| format!("model-{index}")).collect();
        let case = Case {
            fallback_targets: json!(models),
            ..Case::new(json!({"model": "gpt-4o", "api_base": "https://own.example"}))
        };

        assert_eq!(case.run(&names), expected);
    }

    #[rstest]
    #[case::another_group(Some("other-group"), refused("client_id"))]
    #[case::the_same_group(Some("azure-group"), Ok(()))]
    #[case::no_model(Some(""), Ok(()))]
    fn a_model_named_in_the_route_must_opt_in_too(
        names: Names,
        #[case] route_model: Option<&'static str>,
        #[case] expected: Result<(), Rejection>,
    ) {
        let case = Case {
            route_model,
            ..routed(
                &["client_id"],
                json!({"model": "azure-group", "client_id": "caller"}),
            )
        };

        assert_eq!(case.run(&names), expected);
    }

    #[rstest]
    #[case::override_param(
        Err(Rejection::Override { param: "s3_bucket_name".to_owned(), allowlist: Allowlist::Buckets }),
        "Rejected Request: s3_bucket_name is not allowed in request body. Clientside passthrough requires explicit \
admin opt-in via either `general_settings.allow_client_side_credentials = true` (proxy-wide) or \
`configurable_clientside_auth_params` on the deployment in your proxy config.yaml. Relevant Issue: \
https://huntr.com/bounties/4001e1a2-7b7a-4776-a3ae-e6692ec3d997 To allow specific values only, list them in \
`general_settings.allowed_client_side_s3_buckets` or in the team's `metadata.allowed_s3_buckets`."
    )]
    #[case::secret_reference(
        reference("client_id"),
        "Rejected Request: client_id holds a secret reference, which only a deployment or credential a proxy admin \
configures can carry."
    )]
    #[case::server_owned(
        Err(Rejection::ServerOwned { param: "github_copilot_app_id".to_owned(), kind: ServerOwnedKind::GitHubCopilot }),
        "Rejected Request: github_copilot_app_id is a server-owned GitHub Copilot authentication parameter and cannot \
be set in a request body. A proxy admin configures it on the deployment or on a stored credential."
    )]
    fn a_rejection_reads_as_the_proxy_has_always_worded_it(
        #[case] rejection: Result<(), Rejection>,
        #[case] expected: &str,
    ) {
        assert_eq!(
            rejection.map_err(|rejection| rejection.to_string()),
            Err(expected.to_owned())
        );
    }
}
