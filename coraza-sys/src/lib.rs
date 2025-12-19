#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn log_cb(
        ctx: *mut std::ffi::c_void,
        level: coraza_log_level_t,
        msg: *const std::ffi::c_char,
        fields: *const std::ffi::c_char,
    ) {
        println!(
            "log_cb: ctx={:?}, level={:?}, msg={:?}, fields={:?}",
            unsafe { std::ffi::CStr::from_ptr(ctx as *const _) },
            level,
            unsafe { std::ffi::CStr::from_ptr(msg) },
            unsafe { std::ffi::CStr::from_ptr(fields) }
        );
    }

    extern "C" fn error_cb(
        ctx: *mut std::ffi::c_void,
        severity: coraza_severity_t,
        msg: *const std::ffi::c_char,
    ) {
        println!(
            "error_cb: ctx={:?}, severity={:?}, msg={:?}",
            unsafe { std::ffi::CStr::from_ptr(ctx as *const _) },
            severity,
            unsafe { std::ffi::CStr::from_ptr(msg) }
        );
    }

    #[test]
    /// This test is a port of the simple_get.c example from the libcoraza repository.
    fn simple_get() {
        unsafe {
            let config = coraza_new_waf_config();
            let rules = "SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,log,msg:'test 123',status:403\"";
            coraza_add_rules_to_waf_config(config, rules.as_ptr() as *mut _, rules.len());
            coraza_add_log_callback_to_waf_config(
                config,
                Some(log_cb),
                c"context" as *const _ as *mut _,
            );
            coraza_add_error_callback_to_waf_config(
                config,
                Some(error_cb),
                c"context" as *const _ as *mut _,
            );
            let mut err: *mut i8 = std::ptr::null_mut();
            let waf = coraza_new_waf(config, &mut err as *mut _);
            assert_ne!(waf, 0);
            assert!(err.is_null());
            let tx = coraza_new_transaction(waf);
            let source_addr = "127.0.0.1";
            coraza_process_connection(
                tx,
                source_addr.as_ptr() as *mut _,
                source_addr.len(),
                55555,
                std::ptr::null_mut(),
                0,
                80,
            );
            let uri = "/someurl";
            let method = "GET";
            let proto = "HTTP/1.1";
            coraza_process_uri(
                tx,
                uri.as_ptr() as *mut _,
                uri.len(),
                method.as_ptr() as *mut _,
                method.len(),
                proto.as_ptr() as *mut _,
                proto.len(),
            );
            coraza_process_request_headers(tx);
            coraza_process_request_body(tx);
            let response_proto = "HTTP/1.1";
            coraza_process_response_headers(
                tx,
                200,
                response_proto.as_ptr() as *mut _,
                response_proto.len(),
            );
            coraza_process_response_body(tx);
            coraza_process_logging(tx);
            let intervention = coraza_intervention(tx).as_mut().unwrap();
            assert_eq!(intervention.status, 403);
            let action_cstr = std::ffi::CStr::from_ptr(intervention.action);
            assert_eq!(action_cstr.to_str().unwrap(), "deny");
            coraza_free_intervention(intervention);
            coraza_free_transaction(tx);
            coraza_free_waf(waf);
        }
    }
}
