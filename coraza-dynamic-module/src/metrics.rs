use std::collections::HashMap;

use envoy_proxy_dynamic_modules_rust_sdk::*;
use smallvec::SmallVec;

#[derive(Debug)]
pub struct CorazaFilterMetrics {
    skipped_count: EnvoyCounterVecId,
    denied_count: EnvoyCounterVecId,
    allowed_count: EnvoyCounterVecId,
    common_values: SmallVec<[String; Self::EXPECTED_NUM_LABELS]>,
}

impl CorazaFilterMetrics {
    pub const EXPECTED_NUM_LABELS: usize = 10;

    pub fn new<EC: EnvoyHttpFilterConfig>(
        metric_labels: &HashMap<String, String>,
        envoy_filter_config: &mut EC,
    ) -> Result<Self, abi::envoy_dynamic_module_type_metrics_result> {
        let mut common_labels: SmallVec<[(&str, &str); Self::EXPECTED_NUM_LABELS]> = metric_labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        common_labels.sort_by(|(ak, _), (bk, _)| ak.cmp(bk));
        let common_values = common_labels
            .iter()
            .map(|(_, value)| (*value).to_owned())
            .collect();
        Ok(Self {
            skipped_count: envoy_filter_config.define_counter_vec(
                "coraza_skipped_count",
                &common_labels
                    .iter()
                    .map(|(key, _)| *key)
                    .chain(["reason"])
                    .collect::<Vec<&str>>(),
            )?,
            denied_count: envoy_filter_config.define_counter_vec(
                "coraza_denied_count",
                &common_labels
                    .iter()
                    .map(|(key, _)| *key)
                    .chain(["reason"])
                    .collect::<Vec<&str>>(),
            )?,
            allowed_count: envoy_filter_config.define_counter_vec(
                "coraza_allowed_count",
                &common_labels
                    .iter()
                    .map(|(key, _)| *key)
                    .collect::<Vec<&str>>(),
            )?,
            common_values,
        })
    }

    pub fn construct_labels<'a, I: IntoIterator<Item = &'a str>>(
        &'a self,
        other: I,
    ) -> SmallVec<[&'a str; Self::EXPECTED_NUM_LABELS]> {
        self.common_values
            .iter()
            .map(|value| value.as_str())
            .chain(other.into_iter())
            .collect()
    }

    pub fn increment_skipped_count<EHF: EnvoyHttpFilter>(
        &self,
        envoy_filter: &mut EHF,
        reason: &str,
    ) {
        let labels = self.construct_labels([reason]);
        envoy_filter
            .increment_counter_vec(self.skipped_count, &labels, 1)
            .inspect_err(|err| {
                envoy_log_error!("Failed to increment skipped count: {:?}", err);
            })
            .ok();
    }

    pub fn increment_denied_count<EHF: EnvoyHttpFilter>(
        &self,
        envoy_filter: &mut EHF,
        reason: &str,
    ) {
        let labels = self.construct_labels([reason]);
        envoy_filter
            .increment_counter_vec(self.denied_count, &labels, 1)
            .inspect_err(|err| {
                envoy_log_error!("Failed to increment denied count: {:?}", err);
            })
            .ok();
    }

    pub fn increment_allowed_count<EHF: EnvoyHttpFilter>(&self, envoy_filter: &mut EHF) {
        let labels = self.construct_labels(None);
        envoy_filter
            .increment_counter_vec(self.allowed_count, &labels, 1)
            .inspect_err(|err| {
                envoy_log_error!("Failed to increment allowed count: {:?}", err);
            })
            .ok();
    }
}
