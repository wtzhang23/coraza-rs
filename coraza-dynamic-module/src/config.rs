use std::{
    borrow::Borrow, collections::HashMap, net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc,
};

use coraza_rs::{Transaction, Waf};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use serde::{Deserialize, Serialize};

use crate::{filter::CorazaFilter, metrics::CorazaFilterMetrics};

#[derive(Debug, Serialize, Deserialize)]
pub struct CorazaSettings {
    pub metric_labels: Option<HashMap<String, String>>,
    pub directives_map: Option<HashMap<String, Vec<Rule>>>,
    pub default_directives: Option<String>,
    pub connection_config: Option<ConnectionConfig>,
    pub request_config: Option<RequestConfig>,
    pub response_config: Option<ResponseConfig>,
    #[serde(default)]
    pub fail_closed: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub source_address: Option<OriginalAddress>,
    pub destination_address: Option<OriginalAddress>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RequestConfig {
    pub buffer_body_limit: Option<usize>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ResponseConfig {
    pub buffer_body_limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum OriginalAddress {
    Header(String),
    HeaderPair { host: String, port: String },
    Literal { address: SocketAddr },
}

#[derive(Debug)]
pub struct CorazaFilterConfig {
    inner: Arc<CorazaFilterConfigInner>,
}

#[derive(Debug)]
pub struct CorazaFilterConfigInner {
    settings: CorazaSettings,
    metrics: CorazaFilterMetrics,
    wafs: HashMap<String, Waf>,
}

impl CorazaFilterConfigInner {
    pub fn new(
        settings: CorazaSettings,
        metrics: CorazaFilterMetrics,
        wafs: HashMap<String, Waf>,
    ) -> Self {
        Self {
            settings,
            metrics,
            wafs,
        }
    }

    pub fn settings(&self) -> &CorazaSettings {
        &self.settings
    }

    pub fn metrics(&self) -> &CorazaFilterMetrics {
        &self.metrics
    }

    pub fn create_transaction(&self, name: &str) -> Option<Transaction> {
        self.wafs.get(name).and_then(|waf| waf.new_transaction())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    File(PathBuf),
    Inline(String),
}

impl CorazaFilterConfig {
    pub fn new<EC: EnvoyHttpFilterConfig>(
        envoy_filter_config: &mut EC,
        filter_config: &str,
    ) -> Option<Self> {
        let settings: CorazaSettings = serde_json::from_str(filter_config)
            .inspect_err(|err| {
                envoy_log_critical!("Failed to parse Coraza filter config: {}", err);
                envoy_log_critical!("Filter config: {}", filter_config);
            })
            .ok()?;
        let wafs: Option<HashMap<String, Waf>> = settings
            .directives_map
            .iter()
            .flat_map(|dirs| dirs.iter())
            .map(|(name, directives)| {
                let mut waf = Waf::new()?;
                for directive in directives {
                    match directive {
                        Rule::File(path) => waf
                            .add_rule_from_file(path.to_str()?)
                            .inspect_err(|err| {
                                envoy_log_error!("Failed to add rules from file: {}", err)
                            })
                            .ok()?,
                        Rule::Inline(directive) => waf
                            .add_rule(directive)
                            .inspect_err(|err| envoy_log_error!("Failed to add rule: {}", err))
                            .ok()?,
                    }
                }
                Some((name.to_string(), waf))
            })
            .collect();
        let wafs = wafs?;
        let metrics = CorazaFilterMetrics::new(
            settings.metric_labels.as_ref().unwrap_or(&HashMap::new()),
            envoy_filter_config,
        )
        .inspect_err(|err| envoy_log_error!("Failed to create metrics: {:?}", err))
        .ok()?;
        Some(Self {
            inner: Arc::new(CorazaFilterConfigInner::new(settings, metrics, wafs)),
        })
    }

    pub fn clone_inner(&self) -> Arc<CorazaFilterConfigInner> {
        self.inner.clone()
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilterConfig<EHF> for CorazaFilterConfig {
    fn new_http_filter(&mut self, _envoy_filter: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(CorazaFilter::new(self).unwrap())
    }
}

impl Borrow<CorazaFilterConfigInner> for CorazaFilterConfig {
    fn borrow(&self) -> &CorazaFilterConfigInner {
        &self.inner
    }
}

impl Deref for CorazaFilterConfig {
    type Target = CorazaFilterConfigInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Clone)]
pub struct CorazaPerRouteConfig {
    inner: Arc<CorazaPerRouteSettings>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorazaPerRouteSettings {
    pub directive: Option<String>,
}

impl CorazaPerRouteConfig {
    pub fn new(filter_config: &str) -> Option<Self> {
        let settings: CorazaPerRouteSettings = serde_json::from_str(filter_config)
            .inspect_err(|err| {
                envoy_log_error!("Failed to parse Coraza per route settings: {}", err);
                envoy_log_error!("Per route config: {}", filter_config);
            })
            .ok()?;
        Some(Self {
            inner: Arc::new(settings),
        })
    }

    pub fn settings(&self) -> &CorazaPerRouteSettings {
        &self.inner
    }
}
