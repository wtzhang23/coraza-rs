use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result as AnyhowResult};
use coraza_rs::{Intervention, InterventionAction, Transaction};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use http::Method;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use tap::{Pipe, Tap};

use crate::config::{
    CorazaFilterConfig, CorazaFilterConfigInner, CorazaPerRouteConfig, CorazaSettings,
    OriginalAddress,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString, AsRefStr, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum FailureReason {
    TransitionFailed,
    TransactionNotCreated,
    ProcessingFailed,
}

impl FailureReason {
    fn get_reason_str(err: &anyhow::Error) -> &'static str {
        // Try to extract FailureReason from the error chain
        if let Some(fr) = err.downcast_ref::<FailureReason>() {
            match fr {
                FailureReason::TransitionFailed => "transition_failed",
                FailureReason::TransactionNotCreated => "transaction_not_created",
                FailureReason::ProcessingFailed => "processing_failed",
            }
        } else {
            // Check error message for hints
            let err_msg = err.to_string();
            if err_msg.contains("transition") || err_msg.contains("Transition") {
                "transition_failed"
            } else {
                "processing_failed"
            }
        }
    }
}

pub struct CorazaFilter {
    config: Arc<CorazaFilterConfigInner>,
    per_route_config: Option<CorazaPerRouteConfig>,
    tx: Option<Transaction>,
    request_state: WafRequestState,
    response_state: WafResponseState,
    seen_request_body_bytes: usize,
    seen_response_body_bytes: usize,
    entered_response_body: bool,
    proto: Option<String>,
    method: Option<Method>,
    fail_closed: bool,
}

impl CorazaFilter {
    const DEFAULT_FAIL_CLOSED: bool = true;
    pub fn new(config: &mut CorazaFilterConfig) -> Option<Self> {
        let inner = config.clone_inner();
        Some(Self {
            config: inner,
            per_route_config: None,
            tx: None,
            request_state: WafRequestState::Headers,
            response_state: WafResponseState::Headers,
            seen_request_body_bytes: 0,
            seen_response_body_bytes: 0,
            entered_response_body: false,
            proto: None,
            method: None,
            fail_closed: config
                .settings()
                .fail_closed
                .unwrap_or(Self::DEFAULT_FAIL_CLOSED),
        })
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for CorazaFilter {
    fn on_request_headers(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        if let Some(route_config) = envoy_filter.get_most_specific_route_config() {
            self.per_route_config = route_config
                .downcast_ref::<CorazaPerRouteConfig>()
                .tap(|opt| {
                    if opt.is_none() {
                        envoy_log_debug!(
                            "Per route config is the wrong type. Expected {}.",
                            std::any::type_name::<CorazaPerRouteConfig>()
                        );
                    }
                })
                .cloned();
        }
        let tx = if let Some(per_route_config) = self.per_route_config.as_ref() {
            envoy_log_debug!(
                "Using per route config: {:?}",
                per_route_config.settings().directives
            );
            per_route_config
                .settings()
                .directives
                .as_deref()
                .and_then(|d| self.config.create_transaction(d))
        } else {
            envoy_log_debug!("Using default config");
            self.config
                .settings()
                .default_directives
                .as_deref()
                .and_then(|d| self.config.create_transaction(d))
        };
        self.tx = tx;

        match self.on_request_headers_helper(envoy_filter, end_of_stream) {
            Ok(Some(intervention)) => {
                self.tx.take(); // Stop processing the request.
                self.handle_intervention(envoy_filter, intervention);
                abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration
            }
            Ok(None) => {
                if let Some(buffer_body_limit) = self
                    .config
                    .settings()
                    .request_config
                    .as_ref()
                    .and_then(|c| c.buffer_body_limit)
                {
                    if self.seen_request_body_bytes < buffer_body_limit
                        && !end_of_stream
                        // CONNECT requests need to negotiate the tunnel to make progress, so we should not buffer the body.
                        && self.method.as_ref()
                            != Some(&Method::CONNECT)
                    {
                        abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration
                    } else {
                        abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
                    }
                } else {
                    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
                }
            }
            Err(err) => {
                envoy_log_debug!("Error in on_request_headers_helper: {:#}", err);
                let reason = FailureReason::get_reason_str(&err);
                self.tx.take(); // Stop processing the request.
                if self.fail_closed {
                    self.drop(envoy_filter, http::StatusCode::FORBIDDEN, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration
                } else {
                    self.config
                        .metrics()
                        .increment_skipped_count(envoy_filter, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
                }
            }
        }
    }

    fn on_request_body(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_body_status {
        match self.on_request_body_helper(envoy_filter, end_of_stream) {
            Ok(Some(intervention)) => {
                self.tx.take(); // Stop processing the request.
                self.handle_intervention(envoy_filter, intervention);
                abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationNoBuffer
            }
            Ok(None) => {
                if let Some(buffer_body_limit) = self
                    .config
                    .settings()
                    .request_config
                    .as_ref()
                    .and_then(|c| c.buffer_body_limit)
                {
                    if self.seen_request_body_bytes < buffer_body_limit && !end_of_stream {
                        abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndBuffer
                    } else {
                        abi::envoy_dynamic_module_type_on_http_filter_request_body_status::Continue
                    }
                } else {
                    abi::envoy_dynamic_module_type_on_http_filter_request_body_status::Continue
                }
            }
            Err(err) => {
                envoy_log_debug!("Error in on_request_body_helper: {:#}", err);
                let reason = FailureReason::get_reason_str(&err);
                self.tx.take(); // Stop processing the request.
                if self.fail_closed {
                    self.drop(envoy_filter, http::StatusCode::FORBIDDEN, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationNoBuffer
                } else {
                    self.config
                        .metrics()
                        .increment_skipped_count(envoy_filter, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_request_body_status::Continue
                }
            }
        }
    }

    fn on_request_trailers(
        &mut self,
        envoy_filter: &mut EHF,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status {
        match self.on_request_trailers_helper() {
            Ok(Some(intervention)) => {
                self.tx.take(); // Stop processing the request.
                self.handle_intervention(envoy_filter, intervention);
                abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status::StopIteration
            }
            Ok(None) => {
                abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status::Continue
            }
            Err(err) => {
                envoy_log_debug!("Error in on_request_trailers_helper: {:#}", err);
                let reason = FailureReason::get_reason_str(&err);
                self.tx.take(); // Stop processing the request.
                if self.fail_closed {
                    self.drop(envoy_filter, http::StatusCode::FORBIDDEN, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status::StopIteration
                } else {
                    self.config
                        .metrics()
                        .increment_skipped_count(envoy_filter, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_request_trailers_status::Continue
                }
            }
        }
    }

    fn on_response_headers(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_headers_status {
        match self.on_response_headers_helper(envoy_filter, end_of_stream) {
            Ok(Some(intervention)) => {
                self.tx.take(); // Stop processing the request.
                self.handle_intervention(envoy_filter, intervention);
                abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopIteration
            }
            Ok(None) => {
                if let Some(buffer_body_limit) = self
                    .config
                    .settings()
                    .response_config
                    .as_ref()
                    .and_then(|c| c.buffer_body_limit)
                {
                    if self.seen_response_body_bytes < buffer_body_limit
                        && !end_of_stream
                        // CONNECT requests need to negotiate the tunnel to make progress, so we should not buffer the body.
                        && self.method.as_ref() != Some(&Method::CONNECT)
                    {
                        abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopIteration
                    } else {
                        abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
                    }
                } else {
                    abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
                }
            }
            Err(err) => {
                envoy_log_debug!("Error in on_response_headers_helper: {:#}", err);
                let reason = FailureReason::get_reason_str(&err);
                self.tx.take(); // Stop processing the request.
                if self.fail_closed {
                    self.drop(envoy_filter, http::StatusCode::FORBIDDEN, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopIteration
                } else {
                    self.config
                        .metrics()
                        .increment_skipped_count(envoy_filter, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
                }
            }
        }
    }

    fn on_response_body(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_body_status {
        match self.on_response_body_helper(envoy_filter, end_of_stream) {
            Ok(Some(intervention)) => {
                self.tx.take(); // Stop processing the request.
                self.handle_intervention(envoy_filter, intervention);
                abi::envoy_dynamic_module_type_on_http_filter_response_body_status::StopIterationNoBuffer
            }
            Ok(None) => {
                if let Some(buffer_body_limit) = self
                    .config
                    .settings()
                    .response_config
                    .as_ref()
                    .and_then(|c| c.buffer_body_limit)
                {
                    if self.seen_response_body_bytes < buffer_body_limit && !end_of_stream {
                        abi::envoy_dynamic_module_type_on_http_filter_response_body_status::StopIterationAndBuffer
                    } else {
                        abi::envoy_dynamic_module_type_on_http_filter_response_body_status::Continue
                    }
                } else {
                    abi::envoy_dynamic_module_type_on_http_filter_response_body_status::Continue
                }
            }
            Err(err) => {
                envoy_log_debug!("Error in on_response_body_helper: {:#}", err);
                let reason = FailureReason::get_reason_str(&err);
                self.tx.take(); // Stop processing the request.
                if self.fail_closed {
                    self.drop(envoy_filter, http::StatusCode::FORBIDDEN, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_response_body_status::StopIterationNoBuffer
                } else {
                    self.config
                        .metrics()
                        .increment_skipped_count(envoy_filter, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_response_body_status::Continue
                }
            }
        }
    }

    fn on_response_trailers(
        &mut self,
        envoy_filter: &mut EHF,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status {
        match self.on_response_trailers_helper() {
            Ok(Some(intervention)) => {
                self.tx.take(); // Stop processing the request.
                self.handle_intervention(envoy_filter, intervention);
                abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status::StopIteration
            }
            Ok(None) => {
                abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status::Continue
            }
            Err(err) => {
                envoy_log_debug!("Error in on_response_trailers_helper: {:#}", err);
                let reason = FailureReason::get_reason_str(&err);
                self.tx.take(); // Stop processing the request.
                if self.fail_closed {
                    self.drop(envoy_filter, http::StatusCode::FORBIDDEN, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status::StopIteration
                } else {
                    self.config
                        .metrics()
                        .increment_skipped_count(envoy_filter, reason);
                    abi::envoy_dynamic_module_type_on_http_filter_response_trailers_status::Continue
                }
            }
        }
    }

    fn on_stream_complete(&mut self, envoy_filter: &mut EHF) {
        // Process logging to generate audit logs
        if self
            .on_stream_complete_helper()
            .inspect_err(|err| {
                envoy_log_debug!("Error in on_stream_complete: {:#}", err);
            })
            .ok()
            .flatten()
            .is_some()
        {
            envoy_log_debug!("Got intervention after request completion");
        }

        // technically, this includes requests that didn't fully complete; but from the perspective of the
        // WAF, the request was not rejected, so we can count it as allowed.
        if self.tx.is_some() {
            self.config.metrics().increment_allowed_count(envoy_filter);
        }
    }
}

// ************************************************************** */
/* Helper functions for processing the request.                       */
/* ************************************************************** */
impl CorazaFilter {
    fn on_request_headers_helper<'a, 'b, EHF: EnvoyHttpFilter>(
        &'a mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> AnyhowResult<Option<Intervention>>
    where
        'b: 'a,
    {
        if let Some(intervention) = self.transition_waf_request_state(WafRequestState::Headers)? {
            return Ok(Some(intervention));
        }

        let Self {
            config,
            tx,
            proto,
            method,
            ..
        } = self;
        let Some(tx) = tx.as_mut() else {
            return Ok(None);
        };

        // process connection
        (|| -> AnyhowResult<()> {
            let source_address = get_source_address(config.settings(), envoy_filter)
                .context("Failed to get source address")?;
            let destination_address = get_destination_address(config.settings(), envoy_filter)
                .context("Failed to get destination address")?;
            let source_addr_str = source_address.ip().to_string();
            let dest_addr_str = destination_address.ip().to_string();
            tx.process_connection(
                &source_addr_str,
                source_address.port(),
                &dest_addr_str,
                destination_address.port(),
            )
            .context("Failed to process connection in WAF transaction")?;
            Ok(())
        })()
        .context(FailureReason::ProcessingFailed)?;

        // process uri
        (|| -> AnyhowResult<()> {
            let request_method_opt =
                envoy_filter
                    .get_request_header_value(":method")
                    .or_else(|| {
                        envoy_filter.get_attribute_string(
                            abi::envoy_dynamic_module_type_attribute_id::RequestMethod,
                        )
                    });
            let request_method_opt = request_method_opt
                .as_ref()
                .map(|s| s.as_slice().pipe(std::str::from_utf8))
                .transpose()
                .context("Failed to parse request method as UTF-8")?;
            *method = request_method_opt.and_then(|s| s.parse::<Method>().ok());

            let authority_opt = envoy_filter
                .get_request_header_value(":authority")
                .or_else(|| {
                    envoy_filter.get_attribute_string(
                        abi::envoy_dynamic_module_type_attribute_id::RequestHost,
                    )
                });
            let authority_opt = authority_opt
                .as_ref()
                .map(|s| s.as_slice().pipe(std::str::from_utf8))
                .transpose()
                .context("Failed to parse authority as UTF-8")?;
            if let Some(authority) = authority_opt {
                tx.set_server_name(authority)
                    .context("Failed to set server name")?;
                // CRS rules tend to expect Host even with HTTP/2, so we add it here.
                tx.add_request_header(b"Host", authority.as_bytes())
                    .context("Failed to add Host header crafted from :authority")?;
            }

            let path_opt = envoy_filter.get_request_header_value(":path").or_else(|| {
                envoy_filter
                    .get_attribute_string(abi::envoy_dynamic_module_type_attribute_id::RequestPath)
            });
            let path_opt = path_opt
                .as_ref()
                .map(|s| s.as_slice().pipe(std::str::from_utf8))
                .transpose()
                .context("Failed to parse path as UTF-8")?
                .or_else(|| {
                    if method.as_ref() == Some(&Method::CONNECT) {
                        authority_opt
                    } else {
                        None
                    }
                });

            let request_protocol = envoy_filter
                .get_attribute_string(abi::envoy_dynamic_module_type_attribute_id::RequestProtocol)
                .context("Missing RequestProtocol attribute")?;
            let request_protocol = request_protocol
                .as_slice()
                .pipe(std::str::from_utf8)
                .context("Failed to parse request protocol as UTF-8")?;

            *proto = Some(request_protocol.to_string());

            // ProcessURI automatically parses query string parameters from the URI
            // No need to manually parse and add GET arguments (coraza-proxy-wasm doesn't do this either)
            tx.process_uri(
                path_opt.unwrap_or(""),
                request_method_opt.unwrap_or(""),
                request_protocol,
            )
            .context("Failed to process URI")?;
            Ok(())
        })()
        .context(FailureReason::ProcessingFailed)?;

        // process headers
        (|| -> AnyhowResult<()> {
            for (k, v) in envoy_filter.get_request_headers() {
                tx.add_request_header(k.as_slice(), v.as_slice())
                    .context(format!(
                        "Failed to add request header: {}={}",
                        String::from_utf8_lossy(k.as_slice()),
                        String::from_utf8_lossy(v.as_slice())
                    ))?;
            }
            tx.process_request_headers()
                .context("Failed to process request headers in WAF transaction")?;
            Ok(())
        })()
        .context(FailureReason::ProcessingFailed)?;

        self.get_intervention(
            |this| this.transition_waf_request_state(WafRequestState::Finished),
            end_of_stream,
        )
    }

    fn on_request_body_helper<'a, 'b, EHF: EnvoyHttpFilter>(
        &'a mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> AnyhowResult<Option<Intervention>>
    where
        'b: 'a,
    {
        self.entered_response_body = true;
        if let Some(intervention) =
            self.transition_waf_request_state(WafRequestState::RequestBody)?
        {
            return Ok(Some(intervention));
        }

        let Self { tx, .. } = self;
        let Some(tx) = tx.as_mut() else {
            return Ok(None);
        };

        // feed all the request body chunks to the WAF
        for chunk in envoy_filter
            .get_received_request_body()
            .into_iter()
            .flat_map(|cs| cs.into_iter())
        {
            self.seen_request_body_bytes += chunk.as_slice().len();
            tx.append_request_body(chunk.as_slice())
                .context(FailureReason::ProcessingFailed)?;
        }

        self.get_intervention(
            |this| this.transition_waf_request_state(WafRequestState::Finished),
            end_of_stream,
        )
    }

    fn on_request_trailers_helper(&mut self) -> AnyhowResult<Option<Intervention>> {
        if let Some(intervention) = self.transition_waf_request_state(WafRequestState::Trailers)? {
            return Ok(Some(intervention));
        }

        // after request trailers are received, we can guarantee that the request side is complete.
        self.get_intervention(
            |this| this.transition_waf_request_state(WafRequestState::Finished),
            true,
        )
    }
}

// ************************************************************** */
/* Helper functions for handling the response.                    */
/* ************************************************************** */
impl CorazaFilter {
    fn on_response_headers_helper<EHF: EnvoyHttpFilter>(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> AnyhowResult<Option<Intervention>> {
        if let Some(intervention) = self.transition_waf_response_state(WafResponseState::Headers)? {
            return Ok(Some(intervention));
        }

        let Self { tx, proto, .. } = self;
        let Some(tx) = tx.as_mut() else {
            return Ok(None);
        };

        // process headers
        (|| -> AnyhowResult<()> {
            for (k, v) in envoy_filter.get_response_headers() {
                tx.add_response_header(k.as_slice(), v.as_slice())
                    .context(format!(
                        "Failed to add response header: {}={}",
                        String::from_utf8_lossy(k.as_slice()),
                        String::from_utf8_lossy(v.as_slice())
                    ))?;
            }

            let status = envoy_filter
                .get_response_header_value(":status")
                .or_else(|| {
                    envoy_filter.get_attribute_string(
                        abi::envoy_dynamic_module_type_attribute_id::ResponseCode,
                    )
                })
                .context("Missing :status header and ResponseCode attribute")?;
            let status = status
                .as_slice()
                .pipe(std::str::from_utf8)
                .context("Failed to parse status as UTF-8")?;
            let status = status
                .parse::<http::StatusCode>()
                .context("Failed to parse status code")?;

            let response_protocol = proto.as_deref().unwrap_or("HTTP/1.1");

            tx.process_response_headers(status, response_protocol)
                .context("Failed to process response headers")?;
            Ok(())
        })()
        .context(FailureReason::ProcessingFailed)?;

        self.get_intervention(
            |this| this.transition_waf_response_state(WafResponseState::Finished),
            end_of_stream,
        )
    }

    fn on_response_body_helper<EHF: EnvoyHttpFilter>(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> AnyhowResult<Option<Intervention>> {
        if let Some(intervention) =
            self.transition_waf_response_state(WafResponseState::ResponseBody)?
        {
            return Ok(Some(intervention));
        }

        let Self { tx, .. } = self;
        let Some(tx) = tx.as_mut() else {
            return Ok(None);
        };

        // feed all the response body chunks to the WAF
        for chunk in envoy_filter
            .get_received_response_body()
            .into_iter()
            .flat_map(|cs| cs.into_iter())
        {
            self.seen_response_body_bytes += chunk.as_slice().len();
            tx.append_response_body(chunk.as_slice())
                .context(FailureReason::ProcessingFailed)?;
        }

        self.get_intervention(
            |this| this.transition_waf_response_state(WafResponseState::Finished),
            end_of_stream,
        )
    }

    fn on_response_trailers_helper(&mut self) -> AnyhowResult<Option<Intervention>> {
        if let Some(intervention) =
            self.transition_waf_response_state(WafResponseState::Trailers)?
        {
            return Ok(Some(intervention));
        }

        self.get_intervention(
            |this| this.transition_waf_response_state(WafResponseState::Finished),
            true,
        )
    }
}

// ************************************************************** */
/* Helper functions for handling the stream lifecycle.            */
/* ************************************************************** */
impl CorazaFilter {
    fn on_stream_complete_helper(&mut self) -> AnyhowResult<Option<Intervention>> {
        || -> AnyhowResult<Option<Intervention>> {
            if let Some(intervention) =
                self.transition_waf_request_state(WafRequestState::Finished)?
            {
                return Ok(Some(intervention));
            }
            if let Some(intervention) =
                self.transition_waf_response_state(WafResponseState::Finished)?
            {
                return Ok(Some(intervention));
            }
            Ok(None)
        }()?;
        let Some(tx) = self.tx.as_mut() else {
            return Ok(None);
        };

        tx.process_logging()
            .inspect_err(|err| {
                envoy_log_debug!("Error in on_stream_complete: {:#}", err);
            })
            .ok();
        self.get_intervention(
            |this| this.transition_waf_request_state(WafRequestState::Finished),
            true,
        )
    }
}

// ************************************************************** */
/* Helper functions for handling interventions.                   */
/* ************************************************************** */
impl CorazaFilter {
    fn get_intervention<'a, 'b, F>(
        &'a mut self,
        transition_to_finished: F,
        end_of_stream: bool,
    ) -> AnyhowResult<Option<Intervention>>
    where
        'b: 'a,
        F: FnOnce(&'a mut Self) -> AnyhowResult<Option<Intervention>>,
    {
        let Some(tx) = self.tx.as_mut() else {
            return Ok(None);
        };
        if let Some(intervention) = tx.intervention() {
            Ok(Some(intervention))
        } else if end_of_stream {
            transition_to_finished(self)
        } else {
            Ok(None)
        }
    }

    fn handle_intervention<EHF: EnvoyHttpFilter>(
        &mut self,
        envoy_filter: &mut EHF,
        intervention: Intervention,
    ) {
        match intervention.action() {
            Ok(Some(act)) => {
                self.config
                    .metrics()
                    .increment_denied_count(envoy_filter, act.as_ref());
                // We will just handle everything as a drop for now.
                match act {
                    InterventionAction::Deny
                    | InterventionAction::Redirect
                    | InterventionAction::Drop => {
                        self.drop(
                            envoy_filter,
                            intervention.status().unwrap_or(http::StatusCode::FORBIDDEN),
                            act.as_ref(),
                        );
                    }
                }
            }
            Ok(None) => {
                envoy_log_error!("No intervention action found");
                self.drop(envoy_filter, http::StatusCode::FORBIDDEN, "unknown_action");
            }
            Err(err) => {
                envoy_log_error!("Unknown intervention action: {}", err);
                self.drop(envoy_filter, http::StatusCode::FORBIDDEN, err);
            }
        }
    }

    fn drop<EHF: EnvoyHttpFilter>(
        &mut self,
        envoy_filter: &mut EHF,
        status: http::StatusCode,
        reason: &str,
    ) {
        self.config
            .metrics()
            .increment_denied_count(envoy_filter, reason);
        if self.entered_response_body {
            envoy_log_debug!("Got drop action after response headers were sent downstream");
        }
        envoy_filter.send_response(status.as_u16().into(), Vec::new(), None);
    }
}

/* ************************************************************** */
/* Get addresses from various sources.                            */
/* ************************************************************** */

fn get_source_address<EHF: EnvoyHttpFilter>(
    settings: &CorazaSettings,
    envoy_filter: &mut EHF,
) -> AnyhowResult<SocketAddr> {
    match settings
        .connection_config
        .as_ref()
        .and_then(|config| config.source_address.as_ref())
    {
        Some(OriginalAddress::Header(header)) => get_address_from_header(envoy_filter, header),
        Some(OriginalAddress::HeaderPair { host, port }) => {
            get_address_from_headers(envoy_filter, host, port)
        }
        Some(OriginalAddress::Literal { address }) => Ok(*address),
        None => get_address_from_attribute(
            envoy_filter,
            abi::envoy_dynamic_module_type_attribute_id::SourceAddress,
        ),
    }
}

fn get_destination_address<EHF: EnvoyHttpFilter>(
    settings: &CorazaSettings,
    envoy_filter: &mut EHF,
) -> AnyhowResult<SocketAddr> {
    match settings
        .connection_config
        .as_ref()
        .and_then(|config| config.destination_address.as_ref())
    {
        Some(OriginalAddress::Header(header)) => get_address_from_header(envoy_filter, header),
        Some(OriginalAddress::HeaderPair { host, port }) => {
            get_address_from_headers(envoy_filter, host, port)
        }
        Some(OriginalAddress::Literal { address }) => Ok(*address),
        None => get_address_from_attribute(
            envoy_filter,
            abi::envoy_dynamic_module_type_attribute_id::DestinationAddress,
        ),
    }
}

fn get_address_from_header<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    header: &str,
) -> AnyhowResult<SocketAddr> {
    let raw = envoy_filter
        .get_request_header_value(header)
        .context("Address header not found")?;
    let raw = raw
        .as_slice()
        .pipe(std::str::from_utf8)
        .context("Address header not valid UTF-8")?;
    raw.parse().context("Address header not a valid IP address")
}

fn get_address_from_headers<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    host: &str,
    port: &str,
) -> AnyhowResult<SocketAddr> {
    let raw_host = envoy_filter
        .get_request_header_value(host)
        .context("Host header not found")?;
    let raw_port = envoy_filter
        .get_request_header_value(port)
        .context("Port header not found")?;
    let raw_host = raw_host
        .as_slice()
        .pipe(std::str::from_utf8)
        .context("Host header not valid UTF-8")?;
    let raw_port = raw_port
        .as_slice()
        .pipe(std::str::from_utf8)
        .context("Port header not valid UTF-8")?;
    let host = raw_host
        .parse::<IpAddr>()
        .context("Host header not a valid IP address")?;
    let port = raw_port
        .parse::<u16>()
        .context("Port header not a valid port")?;
    Ok(SocketAddr::from((host, port)))
}

fn get_address_from_attribute<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    attribute: abi::envoy_dynamic_module_type_attribute_id,
) -> AnyhowResult<SocketAddr> {
    let raw = envoy_filter
        .get_attribute_string(attribute)
        .context("Address attribute not found")?;
    let raw = raw
        .as_slice()
        .pipe(std::str::from_utf8)
        .context("Address attribute not valid UTF-8")?;
    raw.parse()
        .context("Address attribute not a valid IP address")
}

/* ************************************************************** */
/* WAF request and response states.                                */
/* ************************************************************** */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WafRequestState {
    Headers,
    RequestBody,
    Trailers,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WafResponseState {
    Headers,
    ResponseBody,
    Trailers,
    Finished,
}

impl CorazaFilter {
    fn transition_waf_request_state(
        &mut self,
        desired_state: WafRequestState,
    ) -> AnyhowResult<Option<Intervention>> {
        let Self {
            tx, request_state, ..
        } = self;
        let Some(tx) = tx.as_mut() else {
            return Ok(None);
        };
        while *request_state != desired_state {
            match (*request_state, desired_state) {
                (WafRequestState::Headers, WafRequestState::RequestBody)
                | (WafRequestState::Headers, WafRequestState::Finished) => {
                    // process request headers already handled
                    *request_state = WafRequestState::RequestBody;
                }
                (WafRequestState::RequestBody, WafRequestState::Trailers)
                | (WafRequestState::RequestBody, WafRequestState::Finished) => {
                    *request_state = WafRequestState::Trailers;
                    tx.process_request_body()
                        .context("Failed to process request body")?;
                }
                (WafRequestState::Trailers, WafRequestState::Finished) => {
                    *request_state = WafRequestState::Finished;
                }
                (a, b) if a == b => {
                    // Technically, this is handled by the while loop condition.
                    break;
                }
                (_, _) => {
                    unreachable!(
                        "Invalid transition from {:?} to {:?}",
                        request_state, desired_state
                    );
                }
            }
        }
        Ok(tx.intervention())
    }

    fn transition_waf_response_state(
        &mut self,
        desired_state: WafResponseState,
    ) -> AnyhowResult<Option<Intervention>> {
        let Self {
            tx, response_state, ..
        } = self;
        let Some(tx) = tx.as_mut() else {
            return Ok(None);
        };
        while *response_state != desired_state {
            match (*response_state, desired_state) {
                (WafResponseState::Headers, WafResponseState::ResponseBody)
                | (WafResponseState::Headers, WafResponseState::Finished) => {
                    // process response headers already handled
                    *response_state = WafResponseState::ResponseBody;
                }
                (WafResponseState::ResponseBody, WafResponseState::Trailers)
                | (WafResponseState::ResponseBody, WafResponseState::Finished) => {
                    *response_state = WafResponseState::Trailers;
                    tx.process_response_body()
                        .context("Failed to process response body")?;
                }
                (WafResponseState::Trailers, WafResponseState::Finished) => {
                    *response_state = WafResponseState::Finished;
                }
                (a, b) if a == b => {
                    // Technically, this is handled by the while loop condition.
                    break;
                }
                (_, _) => {
                    unreachable!(
                        "Invalid transition from {:?} to {:?}",
                        response_state, desired_state
                    );
                }
            }
        }
        Ok(tx.intervention())
    }
}
