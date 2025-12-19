use std::{
    borrow::Borrow, collections::HashMap, net::SocketAddr, ops::Deref, path::PathBuf, sync::Arc,
};

use coraza_rs::{LogLevel, Severity, Transaction, Waf, WafConfig};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use serde::{Deserialize, Serialize};
use tap::Tap;

use crate::{filter::CorazaFilter, metrics::CorazaFilterMetrics};

#[derive(Debug, Serialize, Deserialize)]
pub struct CorazaSettings {
    pub metric_labels: Option<HashMap<String, String>>,
    pub directives_map: Option<HashMap<String, Directives>>,
    pub default_directives: Option<String>,
    pub connection_config: Option<ConnectionConfig>,
    pub request_config: Option<RequestConfig>,
    pub response_config: Option<ResponseConfig>,
    pub fail_closed: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Directives {
    pub rules: Vec<Rule>,
    pub error_log: Option<Vec<ErrorLog>>,
    pub debug_log: Option<Vec<DebugLog>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLog {
    pub filter: Severity,
    pub location: ErrorLogLocation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum ErrorLogLocation {
    Stdout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugLog {
    pub filter: LogLevel,
    pub location: DebugLogLocation,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "value")]
#[serde(rename_all = "snake_case")]
pub enum DebugLogLocation {
    Stdout,
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
                let mut config = WafConfig::new();
                for directive in directives.rules.iter() {
                    match directive {
                        Rule::File(path) => {
                            config.add_rules_from_file(path.to_str().tap(|opt| {
                                if opt.is_none() {
                                    envoy_log_error!("Failed to convert path to string")
                                }
                            })?)
                        }
                        Rule::Inline(directive) => config.add_rules(directive),
                    }
                }
                let error_logs: Vec<_> = directives
                    .error_log
                    .as_ref()
                    .iter()
                    .flat_map(|logs| logs.iter())
                    .map(|error_log| (error_log.location.clone(), error_log.clone()))
                    .collect::<HashMap<_, _>>()
                    .into_values()
                    .collect();
                if !error_logs.is_empty() {
                    envoy_log_debug!("Adding error log callback for {}", name);
                    config.add_error_callback(move |severity, msg| {
                        for error_log in error_logs.iter() {
                            if error_log.filter > severity {
                                continue;
                            }
                            match error_log.location {
                                ErrorLogLocation::Stdout => match severity {
                                    Severity::Debug => envoy_log_debug!("{}: {}", severity, msg),
                                    Severity::Info | Severity::Notice => {
                                        envoy_log_info!("{}: {}", severity, msg)
                                    }
                                    Severity::Warning => envoy_log_warn!("{}: {}", severity, msg),
                                    Severity::Error => envoy_log_error!("{}: {}", severity, msg),
                                    Severity::Critical => {
                                        envoy_log_critical!("{}: {}", severity, msg)
                                    }
                                    Severity::Emergency => {
                                        envoy_log_critical!("{}: {}", severity, msg)
                                    }
                                    Severity::Alert => envoy_log_critical!("{}: {}", severity, msg),
                                },
                            }
                        }
                    });
                }
                let debug_logs: Vec<_> = directives
                    .debug_log
                    .as_ref()
                    .iter()
                    .flat_map(|logs| logs.iter())
                    .map(|debug_log| (debug_log.location.clone(), debug_log.clone()))
                    .collect::<HashMap<_, _>>()
                    .into_values()
                    .collect();
                if !debug_logs.is_empty() {
                    envoy_log_debug!("Adding debug log callback for {}", name);
                    config.add_log_callback(move |level, msg, fields| {
                        for debug_log in debug_logs.iter() {
                            if debug_log.filter > level {
                                continue;
                            }
                            match debug_log.location {
                                DebugLogLocation::Stdout => match level {
                                    LogLevel::Trace => {
                                        envoy_log_trace!("{}: {} {}", level, msg, fields)
                                    }
                                    LogLevel::Debug => {
                                        envoy_log_debug!("{}: {} {}", level, msg, fields)
                                    }
                                    LogLevel::Info => {
                                        envoy_log_info!("{}: {} {}", level, msg, fields)
                                    }
                                    LogLevel::Warn => {
                                        envoy_log_warn!("{}: {} {}", level, msg, fields)
                                    }
                                    LogLevel::Error => {
                                        envoy_log_error!("{}: {} {}", level, msg, fields)
                                    }
                                },
                            }
                        }
                    });
                }
                let waf = Waf::new(Arc::new(config))
                    .inspect_err(|err| envoy_log_error!("Failed to create WAF: {}", err))
                    .ok()?;
                envoy_log_debug!("Created WAF for {}", name);
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
    pub directives: Option<String>,
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
