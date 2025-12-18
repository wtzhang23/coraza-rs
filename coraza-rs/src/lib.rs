use std::str::FromStr;

use coraza_sys::*;
use cstr_argument::CStrArgument;
use strum::{AsRefStr, Display, EnumString, IntoStaticStr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Processing failed")]
    ProcessingFailed,
    #[error("Failed to create WAF: {0}")]
    FailedToCreateWaf(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct WafConfig {
    inner: coraza_waf_config_t,
}

impl WafConfig {
    pub fn new() -> Self {
        Self {
            inner: unsafe { coraza_new_waf_config() },
        }
    }

    /// Add rules to the WAF config.
    ///
    /// # Arguments
    ///
    /// * `rules` - The rules to add.
    pub fn add_rules<CStrArg: CStrArgument>(&mut self, rule: CStrArg) {
        unsafe {
            coraza_add_rules_to_waf_config(self.inner, rule.into_cstr().as_ref().as_ptr() as *mut _)
        };
    }

    /// Add rules from a file to the WAF config.
    ///
    /// # Arguments
    ///
    /// * `file` - The file to add rules from.
    pub fn add_rules_from_file<CStrArg: CStrArgument>(&mut self, file: CStrArg) {
        unsafe {
            coraza_add_rules_from_file_to_waf_config(
                self.inner,
                file.into_cstr().as_ref().as_ptr() as *mut _,
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

#[derive(Debug)]
pub struct Waf {
    inner: coraza_waf_t,
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
    pub fn new(config: &WafConfig) -> Result<Self> {
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
        Ok(Self { inner })
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
    pub fn new_transaction_with_id<CStrArg: CStrArgument>(
        &self,
        id: CStrArg,
    ) -> Option<Transaction> {
        let inner = unsafe {
            coraza_new_transaction_with_id(self.inner, id.into_cstr().as_ref().as_ptr() as *mut _)
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
    pub fn process_connection<CStrArg1: CStrArgument, CStrArg2: CStrArgument>(
        &mut self,
        source_address: CStrArg1,
        client_port: u16,
        server_host: CStrArg2,
        server_port: u16,
    ) -> Result<()> {
        let rv = unsafe {
            coraza_process_connection(
                self.inner,
                source_address.into_cstr().as_ref().as_ptr() as *mut _,
                client_port.into(),
                server_host.into_cstr().as_ref().as_ptr() as *mut _,
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
    pub fn process_uri<CStrArg1: CStrArgument, CStrArg2: CStrArgument, CStrArg3: CStrArgument>(
        &mut self,
        uri: CStrArg1,
        method: CStrArg2,
        proto: CStrArg3,
    ) -> Result<()> {
        let rv = unsafe {
            coraza_process_uri(
                self.inner,
                uri.into_cstr().as_ref().as_ptr() as *mut _,
                method.into_cstr().as_ref().as_ptr() as *mut _,
                proto.into_cstr().as_ref().as_ptr() as *mut _,
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
                name.len().try_into().expect("Name length too long"),
                value.as_ptr() as *mut _,
                value.len().try_into().expect("Value length too long"),
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
    pub fn add_get_request_argument<CStrArg1: CStrArgument, CStrArg2: CStrArgument>(
        &mut self,
        name: CStrArg1,
        value: CStrArg2,
    ) -> Result<()> {
        let rv = unsafe {
            coraza_add_get_args(
                self.inner,
                name.into_cstr().as_ref().as_ptr() as *mut _,
                value.into_cstr().as_ref().as_ptr() as *mut _,
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
                name.len().try_into().expect("Name length too long"),
                value.as_ptr() as *mut _,
                value.len().try_into().expect("Value length too long"),
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
    pub fn process_response_headers<CStrArg: CStrArgument>(
        &mut self,
        status: http::StatusCode,
        proto: CStrArg,
    ) -> Result<()> {
        let rv = unsafe {
            coraza_process_response_headers(
                self.inner,
                status.as_u16().into(),
                proto.into_cstr().as_ref().as_ptr() as *mut _,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// This test is a port of the simple_get.c example from the libcoraza repository.
    fn simple_get() {
        let mut config = WafConfig::new();
        config.add_rules(
            "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,log,msg:'test 123',status:403\"",
        );
        let waf = Waf::new(&config).expect("Failed to create WAF");
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
    fn invalid_rule() {
        let mut config = WafConfig::new();
        config.add_rules("foobar");
        let result = Waf::new(&config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            Error::FailedToCreateWaf(e) => {
                println!("{}", e);
            }
            _ => panic!("Expected Error::FailedToCreateWaf"),
        }
    }
}
