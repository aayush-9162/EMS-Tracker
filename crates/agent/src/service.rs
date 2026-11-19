//! Runs the agent core as a Windows service.

use crate::paths::{Ctx, SERVICE_NAME};
use std::ffi::OsString;
use std::time::Duration;
use tokio::sync::watch;
use windows_service::service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

define_windows_service!(ffi_service_main, service_main);

/// Hands the process over to the service control manager. Returns when the service stops.
pub fn run_dispatcher() -> i32 {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => 0,
        Err(e) => {
            // Reached when someone runs `ems-agent service` by hand instead of through the service manager.
            eprintln!("this command is run by the Windows service manager, not directly: {e}");
            1
        }
    }
}

fn status(state: ServiceState, accept: ServiceControlAccept, exit: u32, wait: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(exit),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    let ctx = Ctx::installed();
    crate::logger::init(&ctx.log_path(), false);
    // After an update this is a newer program than the one that was installed by hand.
    crate::install::record_installed_version();

    let (stop_tx, stop_rx) = watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
        crate::log!("could not register with the service manager");
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0, Duration::ZERO));

    let exit = match crate::core::init(ctx) {
        Ok(shared) => match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
            Ok(rt) => {
                rt.block_on(crate::core::run(shared, stop_rx));
                0
            }
            Err(e) => {
                crate::log!("could not start the runtime: {e}");
                1
            }
        },
        Err(e) => {
            crate::log!("startup failed: {e:#}");
            1
        }
    };
    let _ = handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), exit, Duration::ZERO));
}
