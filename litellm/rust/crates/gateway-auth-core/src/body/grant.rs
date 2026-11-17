//! Which deployments a request can reach, and whether all of them let a caller set an override.
//! The router picks the deployment that serves a request, and a failure moves it on to a
//! fallback, so an opt-in counts only when every deployment the request can land on carries it.

use std::collections::BTreeSet;

use super::{
    host::{Deployment, Deployments},
    names::VERTEX_TARGET_PARAMS,
    value::CallerValue,
};

pub(crate) const MAX_FALLBACK_MODELS: usize = 100;

/// Providers that read a Vertex project and location from the call.
const VERTEX_TARGET_READING_PROVIDERS: [&str; 4] = ["vertex_ai", "vertex_ai_beta", "gemini", "gdc"];

/// The deployments of every model group a request can reach, one entry per group.
#[derive(Debug)]
pub(crate) struct Reachable(Vec<Vec<Deployment>>);

impl Reachable {
    /// Follows aliases, the router's fallbacks, and the groups each found deployment routes
    /// under, until no new group turns up.
    pub(crate) fn resolve<D: Deployments>(
        router: &D,
        requested: &BTreeSet<String>,
    ) -> Result<Self, D::Error> {
        let routed = requested
            .iter()
            .map(|name| aliased(router, name))
            .collect::<Result<BTreeSet<_>, _>>()?;
        let mut reached = routed.clone();
        for name in requested.union(&routed) {
            reached.extend(fallback_groups(router, name)?);
        }

        let mut groups = Vec::new();
        let mut frontier = reached.clone();
        while !frontier.is_empty() {
            let mut routed_under = BTreeSet::new();
            for model in &frontier {
                let deployments = router.group(model)?;
                routed_under.extend(
                    deployments
                        .iter()
                        .map(|deployment| deployment.model_name.clone())
                        .filter(|name| !reached.contains(name)),
                );
                groups.push(deployments);
            }
            let mut next = routed_under.clone();
            for name in &routed_under {
                next.extend(fallback_groups(router, name)?);
            }
            next.retain(|name| !reached.contains(name));
            reached.extend(next.iter().cloned());
            frontier = next;
        }
        Ok(Self(groups))
    }

    /// Whether every reachable group lets a caller set `param` to `value`. A Vertex project or
    /// location only has to be allowed by the groups whose provider reads one.
    pub(crate) fn grants<D: Deployments>(
        &self,
        router: &D,
        param: &str,
        value: &CallerValue,
    ) -> Result<bool, D::Error> {
        let names_vertex_target = VERTEX_TARGET_PARAMS.contains(&param);
        for group in &self.0 {
            if names_vertex_target && !reads_vertex_target(group) {
                continue;
            }
            if !group_grants(router, group, param, value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn aliased<D: Deployments>(router: &D, name: &str) -> Result<String, D::Error> {
    Ok(router.alias(name)?.unwrap_or_else(|| name.to_owned()))
}

fn fallback_groups<D: Deployments>(router: &D, name: &str) -> Result<Vec<String>, D::Error> {
    router
        .fallbacks(name)?
        .iter()
        .map(|fallback| aliased(router, fallback))
        .collect()
}

fn reads_vertex_target(group: &[Deployment]) -> bool {
    group.is_empty()
        || group.iter().any(|deployment| {
            deployment
                .provider
                .as_deref()
                .is_none_or(|provider| VERTEX_TARGET_READING_PROVIDERS.contains(&provider))
        })
}

/// A group with no deployment grants nothing.
fn group_grants<D: Deployments>(
    router: &D,
    group: &[Deployment],
    param: &str,
    value: &CallerValue,
) -> Result<bool, D::Error> {
    if group.is_empty() {
        return Ok(false);
    }
    for deployment in group {
        if !deployment_grants(router, deployment, param, value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn deployment_grants<D: Deployments>(
    router: &D,
    deployment: &Deployment,
    param: &str,
    value: &CallerValue,
) -> Result<bool, D::Error> {
    let Some(opt_in) = &deployment.opt_in else {
        return Ok(false);
    };
    if opt_in.params.iter().any(|allowed| allowed == param) {
        return Ok(true);
    }
    let (true, Some(api_base)) = (param == "api_base", value.text()) else {
        return Ok(false);
    };
    for pattern in &opt_in.api_base_patterns {
        if router.api_base_matches(pattern, api_base)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, convert::Infallible};

    use rstest::rstest;

    use super::{super::host::OptIn, *};

    #[derive(Default)]
    struct Router {
        groups: BTreeMap<&'static str, Vec<Deployment>>,
        aliases: BTreeMap<&'static str, &'static str>,
        fallbacks: BTreeMap<&'static str, Vec<&'static str>>,
    }

    impl Deployments for Router {
        type Error = Infallible;

        fn group(&self, model: &str) -> Result<Vec<Deployment>, Infallible> {
            Ok(self.groups.get(model).cloned().unwrap_or_default())
        }

        fn alias(&self, name: &str) -> Result<Option<String>, Infallible> {
            Ok(self.aliases.get(name).map(|group| (*group).to_owned()))
        }

        fn fallbacks(&self, name: &str) -> Result<Vec<String>, Infallible> {
            Ok(self
                .fallbacks
                .get(name)
                .map(|names| names.iter().map(|name| (*name).to_owned()).collect())
                .unwrap_or_default())
        }

        fn api_base_matches(&self, pattern: &str, value: &str) -> Result<bool, Infallible> {
            Ok(pattern == value)
        }
    }

    fn deployment(model_name: &str, provider: &str, params: &[&str]) -> Deployment {
        Deployment {
            model_name: model_name.to_owned(),
            provider: Some(provider.to_owned()),
            opt_in: Some(OptIn {
                params: params.iter().map(|param| (*param).to_owned()).collect(),
                api_base_patterns: vec!["https://allowed.example".to_owned()],
            }),
        }
    }

    fn grants(router: &Router, model: &str, param: &str, value: &str) -> bool {
        let requested = BTreeSet::from([model.to_owned()]);
        let Ok(reachable) = Reachable::resolve(router, &requested);
        let Ok(granted) = reachable.grants(router, param, &CallerValue::Text(value.to_owned()));
        granted
    }

    #[rstest]
    #[case::every_deployment_opts_in(&["client_id"], &["client_id"], true)]
    #[case::one_deployment_does_not(&["client_id"], &[], false)]
    fn a_group_grants_only_what_every_deployment_opts_in_to(
        #[case] first: &[&str],
        #[case] second: &[&str],
        #[case] expected: bool,
    ) {
        let router = Router {
            groups: BTreeMap::from([(
                "azure-group",
                vec![
                    deployment("azure-group", "azure", first),
                    deployment("azure-group", "azure", second),
                ],
            )]),
            ..Router::default()
        };

        assert_eq!(
            grants(&router, "azure-group", "client_id", "caller"),
            expected
        );
    }

    #[rstest]
    #[case::fallback_opts_in(&["client_id"], true)]
    #[case::fallback_does_not(&[], false)]
    fn a_fallback_group_must_opt_in_too(#[case] fallback_params: &[&str], #[case] expected: bool) {
        let router = Router {
            groups: BTreeMap::from([
                (
                    "primary",
                    vec![deployment("primary", "azure", &["client_id"])],
                ),
                (
                    "backup",
                    vec![deployment("backup", "azure", fallback_params)],
                ),
            ]),
            fallbacks: BTreeMap::from([("primary", vec!["backup"])]),
            ..Router::default()
        };

        assert_eq!(grants(&router, "primary", "client_id", "caller"), expected);
    }

    #[rstest]
    fn an_alias_is_judged_by_the_group_it_names() {
        let router = Router {
            groups: BTreeMap::from([(
                "primary",
                vec![deployment("primary", "azure", &["client_id"])],
            )]),
            aliases: BTreeMap::from([("nickname", "primary")]),
            ..Router::default()
        };

        assert!(grants(&router, "nickname", "client_id", "caller"));
    }

    #[rstest]
    fn a_group_reached_only_through_a_deployment_must_opt_in_too() {
        let router = Router {
            groups: BTreeMap::from([
                (
                    "openai/*",
                    vec![deployment("wildcard-group", "openai", &["client_id"])],
                ),
                (
                    "wildcard-group",
                    vec![deployment("wildcard-group", "openai", &[])],
                ),
            ]),
            ..Router::default()
        };

        assert!(!grants(&router, "openai/*", "client_id", "caller"));
    }

    #[rstest]
    fn a_model_no_deployment_serves_grants_nothing() {
        assert!(!grants(
            &Router::default(),
            "unknown",
            "client_id",
            "caller"
        ));
    }

    #[rstest]
    #[case::listed_pattern("https://allowed.example", true)]
    #[case::other_host("https://attacker.example", false)]
    fn an_api_base_is_granted_when_a_pattern_admits_it(
        #[case] value: &str,
        #[case] expected: bool,
    ) {
        let router = Router {
            groups: BTreeMap::from([("primary", vec![deployment("primary", "openai", &[])])]),
            ..Router::default()
        };

        assert_eq!(grants(&router, "primary", "api_base", value), expected);
    }

    #[rstest]
    #[case::other_provider_is_not_asked("openai", true)]
    #[case::vertex_must_opt_in("vertex_ai", false)]
    fn a_vertex_target_is_judged_only_by_groups_that_read_one(
        #[case] fallback_provider: &str,
        #[case] expected: bool,
    ) {
        let router = Router {
            groups: BTreeMap::from([
                (
                    "primary",
                    vec![deployment("primary", "vertex_ai", &["vertex_location"])],
                ),
                ("backup", vec![deployment("backup", fallback_provider, &[])]),
            ]),
            fallbacks: BTreeMap::from([("primary", vec!["backup"])]),
            ..Router::default()
        };

        assert_eq!(
            grants(&router, "primary", "vertex_location", "us-east5"),
            expected
        );
    }
}
