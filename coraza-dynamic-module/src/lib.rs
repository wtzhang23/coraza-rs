use std::any::Any;

use envoy_proxy_dynamic_modules_rust_sdk::*;

use crate::config::{CorazaFilterConfig, CorazaPerRouteConfig};

pub mod config;
pub mod filter;
pub mod metrics;

declare_init_functions!(
    init,
    new_http_filter_config_fn,
    new_http_filter_per_route_config_fn
);

fn init() -> bool {
    true
}

fn new_http_filter_config_fn<EC: EnvoyHttpFilterConfig, EHF: EnvoyHttpFilter>(
    envoy_filter_config: &mut EC,
    filter_name: &str,
    filter_config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>> {
    let filter_config = std::str::from_utf8(filter_config).unwrap();
    match filter_name {
        "coraza" => CorazaFilterConfig::new(envoy_filter_config, filter_config)
            .map(|config| Box::new(config) as Box<_>),
        _ => None,
    }
}

fn new_http_filter_per_route_config_fn(
    filter_name: &str,
    filter_config: &[u8],
) -> Option<Box<dyn Any>> {
    let filter_config = std::str::from_utf8(filter_config).unwrap();
    match filter_name {
        "coraza" => {
            CorazaPerRouteConfig::new(filter_config).map(|config| Box::new(config) as Box<_>)
        }
        _ => None,
    }
}
