#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn log_cb(data: *const std::ffi::c_void) {
        println!("{}", unsafe {
            std::ffi::CStr::from_ptr(data as *const i8).to_string_lossy()
        });
    }

    #[test]
    fn simple_get() {
        unsafe {
            // This is a port of the simple_get.c example from the libcoraza repository
            let waf = coraza_new_waf();
            assert_ne!(waf, 0);
            coraza_set_log_cb(waf, Some(log_cb));
            let mut err = std::ptr::null_mut();
            coraza_rules_add(waf, c"SecRule REMOTE_ADDR \"127.0.0.1\" \"id:1,phase:1,deny,log,msg:'test 123',status:403\"".as_ptr() as *mut _, &mut err);
            assert!(err.is_null());
            let tx = coraza_new_transaction(waf, log_cb as *mut std::ffi::c_void);
            coraza_process_connection(
                tx,
                c"127.0.0.1".as_ptr() as *mut _,
                55555,
                std::ptr::null_mut(),
                80,
            );
            coraza_process_uri(
                tx,
                c"/someurl".as_ptr() as *mut _,
                c"GET".as_ptr() as *mut _,
                c"HTTP/1.1".as_ptr() as *mut _,
            );
            coraza_process_request_headers(tx);
            coraza_process_request_body(tx);
            coraza_process_response_headers(tx, 200, c"HTTP/1.1".as_ptr() as *mut _);
            coraza_process_response_body(tx);
            coraza_process_logging(tx);
            let intervention = coraza_intervention(tx).as_mut().unwrap();
            assert_eq!(intervention.status, 403);
            assert_eq!(std::ffi::CStr::from_ptr(intervention.action), c"deny");
            assert_eq!(intervention.disruptive, 0);
            assert_eq!(intervention.pause, 0);
            coraza_free_intervention(intervention);
            coraza_free_transaction(tx);
            coraza_free_waf(waf);
        }
    }
}
