use std::{pin::Pin, str::FromStr, sync::Arc};

use coraza_sys::*;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use thiserror::Error;

#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
#[cfg_attr(feature = "serde", serde(content = "value"))]
pub enum Error {
    #[error("Processing failed")]
    ProcessingFailed,
    #[error("Failed to create WAF: {0}")]
    FailedToCreateWaf(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    EnumString,
    AsRefStr,
    IntoStaticStr,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<coraza_log_level_t> for LogLevel {
    fn from(level: coraza_log_level_t) -> Self {
        match level {
            coraza_log_level_t::CORAZA_LOG_LEVEL_TRACE => LogLevel::Trace,
            coraza_log_level_t::CORAZA_LOG_LEVEL_DEBUG => LogLevel::Debug,
            coraza_log_level_t::CORAZA_LOG_LEVEL_INFO => LogLevel::Info,
            coraza_log_level_t::CORAZA_LOG_LEVEL_WARN => LogLevel::Warn,
            coraza_log_level_t::CORAZA_LOG_LEVEL_ERROR => LogLevel::Error,
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Display,
    EnumString,
    AsRefStr,
    IntoStaticStr,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Severity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl From<coraza_severity_t> for Severity {
    fn from(severity: coraza_severity_t) -> Self {
        match severity {
            coraza_severity_t::CORAZA_SEVERITY_EMERGENCY => Severity::Emergency,
            coraza_severity_t::CORAZA_SEVERITY_ALERT => Severity::Alert,
            coraza_severity_t::CORAZA_SEVERITY_CRITICAL => Severity::Critical,
            coraza_severity_t::CORAZA_SEVERITY_ERROR => Severity::Error,
            coraza_severity_t::CORAZA_SEVERITY_WARNING => Severity::Warning,
            coraza_severity_t::CORAZA_SEVERITY_NOTICE => Severity::Notice,
            coraza_severity_t::CORAZA_SEVERITY_INFO => Severity::Info,
            coraza_severity_t::CORAZA_SEVERITY_DEBUG => Severity::Debug,
        }
    }
}

#[derive(Debug)]
pub struct WafConfig {
    inner: coraza_waf_config_t,
    added_raw_log_callback: bool,
    added_raw_error_callback: bool,
    callback_context: Option<Pin<Box<WafCallbackContext>>>,
}

type LogCallback = Box<dyn Fn(LogLevel, String, String) + Send + Sync>;
type ErrorCallback = Box<dyn Fn(Severity, String) + Send + Sync>;

pub struct WafCallbackContext {
    log_callback: Option<LogCallback>,
    error_callback: Option<ErrorCallback>,
}

impl WafConfig {
    pub fn new() -> Self {
        Self {
            inner: unsafe { coraza_new_waf_config() },
            added_raw_log_callback: false,
            added_raw_error_callback: false,
            callback_context: None,
        }
    }

    pub fn add_log_callback<F: Fn(LogLevel, String, String) + Send + Sync + 'static>(
        &mut self,
        callback: F,
    ) {
        let context = self.callback_context.get_or_insert_with(|| {
            Box::pin(WafCallbackContext {
                log_callback: None,
                error_callback: None,
            })
        });
        context.log_callback = Some(Box::new(callback));
        if !self.added_raw_log_callback {
            unsafe {
                coraza_add_log_callback_to_waf_config(
                    self.inner,
                    Some(log_callback),
                    std::ptr::null_mut(),
                );
            }
            self.added_raw_log_callback = true;
        }
        unsafe {
            coraza_add_log_callback_to_waf_config(
                self.inner,
                Some(log_callback),
                context.as_ref().get_ref() as *const _ as *mut _,
            );
        }
    }

    pub fn add_error_callback<F: Fn(Severity, String) + Send + Sync + 'static>(
        &mut self,
        callback: F,
    ) {
        let context = self.callback_context.get_or_insert_with(|| {
            Box::pin(WafCallbackContext {
                log_callback: None,
                error_callback: None,
            })
        });
        context.error_callback = Some(Box::new(callback));
        if !self.added_raw_error_callback {
            unsafe {
                coraza_add_error_callback_to_waf_config(
                    self.inner,
                    Some(error_callback),
                    std::ptr::null_mut(),
                );
            }
            self.added_raw_error_callback = true;
        }
        unsafe {
            coraza_add_error_callback_to_waf_config(
                self.inner,
                Some(error_callback),
                context.as_ref().get_ref() as *const _ as *mut _,
            );
        }
    }

    /// Add rules to the WAF config.
    ///
    /// # Arguments
    ///
    /// * `rules` - The rules to add.
    pub fn add_rules(&mut self, rule: &str) {
        let len = rule.len();
        unsafe {
            coraza_add_rules_to_waf_config(
                self.inner,
                rule.as_ptr() as *mut _,
                len,
            )
        };
    }

    /// Add rules from a file to the WAF config.
    ///
    /// # Arguments
    ///
    /// * `file` - The file to add rules from.
    pub fn add_rules_from_file(&mut self, file: &str) {
        let len = file.len();
        unsafe {
            coraza_add_rules_from_file_to_waf_config(
                self.inner,
                file.as_ptr() as *mut _,
                len,
            )
        };
    }
}

impl Default for WafConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WafConfig {
    fn drop(&mut self) {
        let rv = unsafe { coraza_free_waf_config(self.inner) };
        debug_assert!(rv == 0, "Failed to free WAF config");
    }
}

impl std::fmt::Debug for WafCallbackContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WafCallbackContext {{ log_callback: {}, error_callback: {} }}",
            match &self.log_callback {
                Some(_) => "Some(<callback>)",
                None => "None",
            },
            match &self.error_callback {
                Some(_) => "Some(<callback>)",
                None => "None",
            },
        )
    }
}

#[derive(Debug)]
pub struct Waf {
    inner: coraza_waf_t,

    // keep a reference to the config to ensure it doesn't get freed while the WAF is alive
    _config: Arc<WafConfig>,
}

impl Waf {
    /// Create a new WAF.
    ///
    /// # Returns
    ///
    /// * `Some(Waf)` - If the WAF was created successfully.
    /// * `None` - If the WAF was not created successfully. This in practice
    ///   won't happen, but is included for completeness.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. See [coraza.WAF](https://pkg.go.dev/github.com/corazawaf/coraza/v3#WAF) for more details.
    pub fn new(config: Arc<WafConfig>) -> Result<Self> {
        let mut raw_err: coraza_error_t = std::ptr::null_mut();
        let inner = unsafe { coraza_new_waf(config.inner, &mut raw_err as *mut _) };
        if inner == 0 {
            let err = unsafe { std::ffi::CStr::from_ptr(raw_err) }
                .to_string_lossy()
                .to_string();
            unsafe {
                coraza_free_error(raw_err);
            };
            return Err(Error::FailedToCreateWaf(err));
        }
        Ok(Self {
            inner,
            _config: config,
        })
    }

    /// Create a new transaction.
    ///
    /// # Returns
    ///
    /// * `Some(Transaction)` - If the transaction was created successfully.
    /// * `None` - If the transaction was not created successfully. This in practice
    ///   won't happen, but is included for completeness.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. See [coraza.WAF](https://pkg.go.dev/github.com/corazawaf/coraza/v3#WAF) for more details.
    /// However, due to crossing the FFI boundary, a lock is required internally to ensure thread safety.
    pub fn new_transaction(&self) -> Option<Transaction> {
        // TODO: allow passing a log callback. Currently, libcoraza does not support this.
        let inner = unsafe { coraza_new_transaction(self.inner) };
        if inner == 0 {
            return None;
        }
        Some(Transaction { inner })
    }

    /// Create a new transaction with an ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the transaction.
    ///
    /// # Returns
    ///
    /// * `Some(Transaction)` - If the transaction was created successfully.
    /// * `None` - If the transaction was not created successfully. This in practice
    ///   won't happen, but is included for completeness.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. See [coraza.WAF](https://pkg.go.dev/github.com/corazawaf/coraza/v3#WAF) for more details.
    /// However, due to crossing the FFI boundary, a lock is required internally to ensure thread safety.
    pub fn new_transaction_with_id(&self, id: &str) -> Option<Transaction> {
        let len = id.len();
        let inner = unsafe {
            coraza_new_transaction_with_id(
                self.inner,
                id.as_ptr() as *mut _,
                len,
            )
        };

        if inner == 0 {
            return None;
        }
        Some(Transaction { inner })
    }
}

impl Drop for Waf {
    fn drop(&mut self) {
        let rv = unsafe { coraza_free_waf(self.inner) };
        debug_assert!(rv == 0, "Failed to free WAF");
    }
}

#[derive(Debug)]
pub struct Transaction {
    inner: coraza_transaction_t,
}

impl Transaction {
    /// Process the connection.
    ///
    /// # Arguments
    ///
    /// * `source_address` - The source address of the connection.
    /// * `client_port` - The client port of the connection.
    /// * `server_host` - The server host of the connection.
    /// * `server_port` - The server port of the connection.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the connection was processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the connection was not processed successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn process_connection(
        &mut self,
        source_address: &str,
        client_port: u16,
        server_host: &str,
        server_port: u16,
    ) -> Result<()> {
        let source_len = source_address.len();
        let server_len = server_host.len();
        let rv = unsafe {
            coraza_process_connection(
                self.inner,
                source_address.as_ptr() as *mut _,
                source_len,
                client_port.into(),
                server_host.as_ptr() as *mut _,
                server_len,
                server_port.into(),
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Process the request body.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the request body was processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the request body was not processed successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn process_request_body(&mut self) -> Result<()> {
        let rv = unsafe { coraza_process_request_body(self.inner) };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Process the URI.
    ///
    /// # Arguments
    ///
    /// * `uri` - The URI to process.
    /// * `method` - The method to process.
    /// * `proto` - The protocol to process.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the URI was processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the URI was not processed successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn process_uri(
        &mut self,
        uri: &str,
        method: &str,
        proto: &str,
    ) -> Result<()> {
        let uri_len = uri.len();
        let method_len = method.len();
        let proto_len = proto.len();
        let rv = unsafe {
            coraza_process_uri(
                self.inner,
                uri.as_ptr() as *mut _,
                uri_len,
                method.as_ptr() as *mut _,
                method_len,
                proto.as_ptr() as *mut _,
                proto_len,
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Add a request header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header.
    /// * `value` - The value of the header.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the request header was added successfully.
    /// * `Err(Error::ProcessingFailed)` - If the request header was not added successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn add_request_header(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        let rv = unsafe {
            coraza_add_request_header(
                self.inner,
                name.as_ptr() as *mut _,
                name.len(),
                value.as_ptr() as *mut _,
                value.len(),
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Process the request headers.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the request headers were processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the request headers were not processed successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn process_request_headers(&mut self) -> Result<()> {
        let rv = unsafe { coraza_process_request_headers(self.inner) };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Process the logging.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the logging was processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the logging was not processed successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn process_logging(&mut self) -> Result<()> {
        let rv = unsafe { coraza_process_logging(self.inner) };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Append the request body.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to append.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the request body was appended successfully.
    /// * `Err(Error::ProcessingFailed)` - If the request body was not appended successfully.
    pub fn append_request_body(&mut self, data: &[u8]) -> Result<()> {
        let rv = unsafe {
            coraza_append_request_body(
                self.inner,
                data.as_ptr() as *mut _,
                data.len().try_into().expect("Data length too long"),
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Add a GET request argument.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the argument.
    /// * `value` - The value of the argument.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the GET request argument was added successfully.
    /// * `Err(Error::ProcessingFailed)` - If the GET request argument was not added successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn add_get_request_argument(
        &mut self,
        name: &str,
        value: &str,
    ) -> Result<()> {
        let name_len = name.len();
        let value_len = value.len();
        let rv = unsafe {
            coraza_add_get_args(
                self.inner,
                name.as_ptr() as *mut _,
                name_len,
                value.as_ptr() as *mut _,
                value_len,
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Add a response header.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header.
    /// * `value` - The value of the header.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the response header was added successfully.
    /// * `Err(Error::ProcessingFailed)` - If the response header was not added successfully. This in practice
    ///   won't happen, but is included for completeness.
    pub fn add_response_header(&mut self, name: &[u8], value: &[u8]) -> Result<()> {
        let rv = unsafe {
            coraza_add_response_header(
                self.inner,
                name.as_ptr() as *mut _,
                name.len(),
                value.as_ptr() as *mut _,
                value.len(),
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Append the response body.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to append.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the response body was appended successfully.
    /// * `Err(Error::ProcessingFailed)` - If the response body was not appended successfully.
    pub fn append_response_body(&mut self, data: &[u8]) -> Result<()> {
        let rv = unsafe {
            coraza_append_response_body(
                self.inner,
                data.as_ptr() as *mut _,
                data.len().try_into().expect("Data length too long"),
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Process the response body.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the response body was processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the response body was not processed successfully.
    pub fn process_response_body(&mut self) -> Result<()> {
        let rv = unsafe { coraza_process_response_body(self.inner) };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Process the response headers.
    ///
    /// # Arguments
    ///
    /// * `status` - The status code of the response.
    /// * `proto` - The protocol of the response.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the response headers were processed successfully.
    /// * `Err(Error::ProcessingFailed)` - If the response headers were not processed successfully.
    pub fn process_response_headers(
        &mut self,
        status: http::StatusCode,
        proto: &str,
    ) -> Result<()> {
        let proto_len = proto.len();
        let rv = unsafe {
            coraza_process_response_headers(
                self.inner,
                status.as_u16().into(),
                proto.as_ptr() as *mut _,
                proto_len,
            )
        };
        if rv != 0 {
            return Err(Error::ProcessingFailed);
        }
        Ok(())
    }

    /// Get the intervention of the transaction.
    ///
    /// # Returns
    ///
    /// * `Some(Intervention)` - If the intervention was found.
    /// * `None` - If the intervention was not found. This signifies that the transaction was not interrupted and that
    ///   the request is currently not being blocked and should continue to be processed.
    pub fn intervention(&mut self) -> Option<Intervention> {
        let inner = unsafe { coraza_intervention(self.inner) };
        if inner.is_null() {
            return None;
        }
        Some(Intervention {
            inner: unsafe { &mut *inner },
        })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        let rv = unsafe { coraza_free_transaction(self.inner) };
        debug_assert!(rv == 0, "Failed to free transaction");
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Display,
    EnumString,
    IntoStaticStr,
    AsRefStr,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub enum InterventionAction {
    #[strum(serialize = "drop")]
    Drop,
    #[strum(serialize = "deny")]
    Deny,
    #[strum(serialize = "redirect")]
    Redirect,
}

#[derive(Debug)]
pub struct Intervention {
    inner: &'static mut coraza_intervention_t,
}

impl Intervention {
    /// Get the action of the intervention.
    pub fn action(&self) -> std::result::Result<Option<InterventionAction>, &'_ str> {
        if self.inner.action.is_null() {
            return Ok(None);
        }
        // The action is converted from a golang string which is UTF-8 encoded, so this should never fail.
        let action = unsafe { std::ffi::CStr::from_ptr(self.inner.action) }
            .to_str()
            .expect("Failed to convert action to string");
        if action.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            InterventionAction::from_str(action).map_err(|_| action)?,
        ))
    }

    /// Get the status code of the intervention.
    pub fn status(&self) -> Option<http::StatusCode> {
        http::StatusCode::from_u16(self.inner.status as u16).ok()
    }
}

impl Drop for Intervention {
    fn drop(&mut self) {
        let rv = unsafe { coraza_free_intervention(self.inner) };
        debug_assert!(rv == 0, "Failed to free intervention");
    }
}

extern "C" fn log_callback(
    ctx: *mut std::ffi::c_void,
    level: coraza_log_level_t,
    msg: *const std::ffi::c_char,
    fields: *const std::ffi::c_char,
) {
    let context = unsafe {
        (ctx as *mut WafCallbackContext)
            .as_mut()
            .expect("Failed to get context")
    };
    (context.log_callback.as_ref().unwrap())(
        level.into(),
        unsafe { std::ffi::CStr::from_ptr(msg) }
            .to_string_lossy()
            .to_string(),
        unsafe { std::ffi::CStr::from_ptr(fields) }
            .to_string_lossy()
            .to_string(),
    );
}

extern "C" fn error_callback(
    ctx: *mut std::ffi::c_void,
    severity: coraza_severity_t,
    msg: *const std::ffi::c_char,
) {
    let context = unsafe {
        (ctx as *mut WafCallbackContext)
            .as_mut()
            .expect("Failed to get context")
    };
    (context.error_callback.as_ref().unwrap())(
        severity.into(),
        unsafe { std::ffi::CStr::from_ptr(msg) }
            .to_string_lossy()
            .to_string(),
    );
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Mutex};

    use super::*;

    #[test]
    /// This test is a port of the simple_get.c example from the libcoraza repository.
    fn simple_get() {
        let mut config = WafConfig::new();
        config.add_rules(
            "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,log,msg:'test 123',status:403\"",
        );
        config.add_log_callback(|level, msg, fields| {
            println!("log: level={}, msg={}, fields={}", level, msg, fields);
        });
        config.add_error_callback(|severity, msg| {
            println!("error: severity={}, msg={}", severity, msg);
        });
        let config = Arc::new(config);
        let waf = Waf::new(config).expect("Failed to create WAF");
        let mut tx = waf.new_transaction().unwrap();
        tx.process_connection("127.0.0.1", 55555, "127.0.0.1", 80)
            .unwrap();
        tx.process_uri("/someurl", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.process_response_headers(http::StatusCode::OK, "HTTP/1.1")
            .unwrap();
        tx.process_response_body().unwrap();
        tx.process_logging().unwrap();
        let intervention = tx.intervention().unwrap();
        assert_eq!(intervention.status(), Some(http::StatusCode::FORBIDDEN));
        assert_eq!(
            intervention.action().unwrap().unwrap(),
            InterventionAction::Deny
        );
    }

    #[test]
    fn error_callback() {
        let mut config = WafConfig::new();
        config.add_rules(
            "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,log,msg:'test 123',status:403\"",
        );
        let callback_value: Arc<Mutex<Vec<(Severity, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let cv = callback_value.clone();
        config.add_error_callback(move |severity, msg| {
            cv.lock().unwrap().push((severity, msg));
        });
        let config = Arc::new(config);
        let waf = Waf::new(config).expect("Failed to create WAF");
        let mut tx = waf.new_transaction().unwrap();
        tx.process_connection("127.0.0.1", 55555, "127.0.0.1", 80)
            .unwrap();
        tx.process_uri("/someurl", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(
            callback_value.lock().unwrap().as_slice(),
            vec![(Severity::Emergency, "test 123".to_string())]
        );
    }

    #[test]
    fn invalid_rule() {
        let mut config = WafConfig::new();
        config.add_rules("foobar");
        let config = Arc::new(config);
        let result = Waf::new(config);
        assert!(result.is_err());
        let err = result.expect_err("Expected error");
        match err {
            Error::FailedToCreateWaf(e) => {
                println!("{}", e);
            }
            _ => panic!("Expected Error::FailedToCreateWaf"),
        }
    }

    #[test]
    fn coreruleset_fs() {
        let mut config = WafConfig::new();
        config.add_rules("Include @owasp_crs/*.conf");
        config.add_rules("Include @coraza.conf-recommended");
        config.add_rules("Include @crs-setup.conf.example");
        let config = Arc::new(config);
        let waf = Waf::new(config).expect("Failed to create WAF");
        waf.new_transaction().unwrap();
    }

    #[test]
    fn local_fs() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let file_path = manifest_dir.join("src").join("testdata").join("test.conf");
        assert!(file_path.exists());
        let mut config = WafConfig::new();
        config.add_rules_from_file(file_path.to_str().unwrap());
        let config = Arc::new(config);
        let waf = Waf::new(config).expect("Failed to create WAF");
        let mut tx = waf.new_transaction().unwrap();
        tx.process_connection("127.0.0.1", 55555, "127.0.0.1", 80)
            .unwrap();
        tx.process_uri("/someurl", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        let intervention = tx.intervention().unwrap();
        assert_eq!(intervention.status(), Some(http::StatusCode::FORBIDDEN));
        assert_eq!(
            intervention.action().unwrap().unwrap(),
            InterventionAction::Deny
        );
    }
}
