//! EMS endpoint agent.
//!
//! One executable, three roles:
//!   `service`  the background service: server check-ins, upload queue, blocking;
//!   `session`  the per-user tray helper: sees the foreground window, shows the icon;
//!   the rest   setup. Double-clicking the file installs it; the same steps
//!              exist as commands for deployment tools.
//!
//! Built for the Windows GUI subsystem so the tray helper never flashes a
//! console window at sign-in. Commands attach to the console they were
//! started from.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("ems-agent runs on Windows only");
    std::process::exit(1);
}

#[cfg(windows)]
mod config;
#[cfg(windows)]
mod core;
#[cfg(windows)]
mod guard;
#[cfg(windows)]
mod install;
#[cfg(windows)]
mod inventory;
#[cfg(windows)]
mod ipc;
#[cfg(windows)]
mod launcher;
#[cfg(windows)]
mod logger;
#[cfg(windows)]
mod paths;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod power;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod session;
#[cfg(windows)]
mod spool;
#[cfg(windows)]
mod sync;
#[cfg(windows)]
mod update;

/// The version, kept in the program as text the server can find: it reads
/// the version of the agent it hands out from the file, without running it.
/// The text before the number is `ems_proto::VERSION_TAG`.
#[cfg(windows)]
pub static VERSION_TAG: &str = concat!("EMS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), ";");

/// This program's version, read back out of [`VERSION_TAG`] so the text is always part of the program.
#[cfg(windows)]
pub fn version() -> &'static str {
    let tag = std::hint::black_box(VERSION_TAG);
    tag.strip_prefix(ems_proto::VERSION_TAG).and_then(|v| v.strip_suffix(';')).unwrap_or(env!("CARGO_PKG_VERSION"))
}

#[cfg(windows)]
fn main() {
    std::process::exit(cli::main());
}

#[cfg(windows)]
mod cli {
    use crate::config::{self, AgentConfig};
    use crate::install;
    use crate::paths::{Ctx, PolicyHive, UpdateMode, DEFAULT_PIPE};
    use anyhow::{bail, Context};
    use std::path::PathBuf;

    const USAGE: &str = "\
EMS Agent

Double-click this file to install it. It asks for administrator rights,
installs, starts, and says whether it reached the server.

Commands, for scripts and deployment tools (run elevated):
  ems-agent install [--server <address>] [--key <agent-key>]
        Install or upgrade and start. Without --server the address comes
        from the installer itself, from ems-agent.json next to it, or from
        the installation already on this computer.
  ems-agent uninstall [--keep-data]
        Stop and remove the agent and lift all site blocking.
  ems-agent status
        Show whether the agent is reaching the server and what it is doing.
  ems-agent settings
        Show which server this installer would use, and where it got that from.
  ems-agent version

Development:
  ems-agent run --data-dir <dir> [--server <address>] [--key <key>] [--pipe <name>]
                [--enforce machine|user] [--hosts-file <path>] [--self-update]
        Run the background part in the foreground with its own data directory.
        Blocking is not applied unless --enforce is given. Writing browser
        policy needs an elevated prompt for either choice; the hosts file
        defaults to a plain file in the data directory. With --self-update
        the run replaces its own program file when the server offers another.
  ems-agent session [--pipe <name>]
        Run the tray helper against a development run.
  ems-agent dev-browser <window-handle> [--close]
        Show what the agent reads from a browser window (address bar and
        page address) and, with --close, close its selected tab.
  ems-agent inventory
        Print this computer's system summary and installed programs (the
        same snapshot the agent uploads), as JSON. For checking what is seen.
";

    /// Value following `--name`, if present.
    fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
    }

    fn flag(args: &[String], name: &str) -> bool {
        args.iter().any(|a| a == name)
    }

    /// `--pipe` accepts a short name; the `\\.\pipe\` prefix is added when missing.
    fn pipe_name(args: &[String], default: &str) -> String {
        const PREFIX: &str = r"\\.\pipe\";
        match opt(args, "--pipe") {
            Some(p) if p.starts_with(PREFIX) => p.to_string(),
            Some(p) => format!("{PREFIX}{}", p.trim_start_matches(['\\', '.', '/'])),
            None => default.to_string(),
        }
    }

    /// A GUI-subsystem program has no console of its own. When started from
    /// one, attach to it so output is visible. Redirected output is left alone.
    fn attach_console() {
        use windows::core::w;
        use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
        use windows::Win32::System::Console::{AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
        unsafe {
            let has_stdout = GetStdHandle(STD_OUTPUT_HANDLE).is_ok_and(|h| !h.is_invalid() && !h.0.is_null());
            if has_stdout || AttachConsole(ATTACH_PARENT_PROCESS).is_err() {
                return;
            }
            if let Ok(out) = CreateFileW(w!("CONOUT$"), (GENERIC_READ | GENERIC_WRITE).0, FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None) {
                let _ = SetStdHandle(STD_OUTPUT_HANDLE, out);
                let _ = SetStdHandle(STD_ERROR_HANDLE, out);
                println!();
            }
        }
    }

    pub fn main() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let gui = flag(&args, "--gui");
        match args.first().map(String::as_str) {
            // No arguments: the file was double-clicked.
            None => return setup(),
            Some("service") => return crate::service::run_dispatcher(),
            Some("session") => return crate::session::run(&pipe_name(&args, DEFAULT_PIPE)),
            Some("install") if gui => return install_with_dialog(),
            // The elevated half of a double-click install: quiet on success, the caller reports.
            Some("install") if flag(&args, "--from-setup") => {
                return match install::install(None, None) {
                    Ok(done) if done.connected => 0,
                    Ok(_) => install::EXIT_NOT_CONNECTED,
                    Err(e) => {
                        install::message_box(&format!("EMS Agent could not be installed.\n\n{e:#}"), true);
                        1
                    }
                };
            }
            Some("uninstall") if gui => return uninstall_with_dialog(),
            // Run from a freshly downloaded copy, to put it in place of the running agent.
            Some("apply-update") => return i32::from(crate::update::apply(&args[1..]).is_err()),
            _ => {}
        }
        attach_console();
        let result = match args[0].as_str() {
            "install" => install::install(opt(&args, "--server"), opt(&args, "--key")).map(|done| println!("{}", done.summary())),
            "uninstall" => install::uninstall(!flag(&args, "--keep-data")).map(|removed| {
                for note in &removed.notes {
                    println!("warning: {note}");
                }
                println!("EMS Agent has been removed from this computer.");
                if let Some(dir) = &removed.leftover_dir {
                    install::remove_dir_after_exit(dir);
                }
            }),
            "status" => status(&pipe_name(&args, DEFAULT_PIPE)).map(|text| println!("{text}")),
            "settings" => std::env::current_exe().map_err(anyhow::Error::from).and_then(|exe| {
                let (cfg, source) = config::discover_setup(opt(&args, "--server"), opt(&args, "--key"), &exe, install::installed_config())?;
                println!("server        {}", cfg.server_url);
                println!("organisation  {}", cfg.org.as_deref().unwrap_or("not named by this installer"));
                println!("agent key     {}", if cfg.key.is_some() { "included" } else { "none" });
                println!("taken from    {source}");
                Ok(())
            }),
            "run" => run(&args),
            "dev-browser" => match args.get(1).and_then(|h| h.parse::<isize>().ok()) {
                Some(hwnd) => {
                    println!("{}", crate::session::dev_browser(hwnd, flag(&args, "--close")));
                    Ok(())
                }
                None => Err(anyhow::anyhow!("usage: ems-agent dev-browser <window-handle> [--close]")),
            },
            "inventory" => {
                let ctx = Ctx::installed();
                let server = install::installed_config().map(|c| c.server_url).unwrap_or_default();
                let inv = crate::inventory::collect(&server, &ctx.log_path());
                match serde_json::to_string_pretty(&inv) {
                    Ok(json) => {
                        println!("{json}");
                        eprintln!("\n{} program(s); fingerprint {}", inv.apps.len(), inv.fingerprint());
                        Ok(())
                    }
                    Err(e) => Err(anyhow::anyhow!("{e}")),
                }
            }
            "version" | "--version" | "-V" => {
                println!("ems-agent {}", crate::version());
                Ok(())
            }
            "help" | "--help" | "-h" | "/?" => {
                print!("{USAGE}");
                Ok(())
            }
            other => Err(anyhow::anyhow!("unknown command {other:?}\n\n{USAGE}")),
        };
        match result {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e:#}");
                1
            }
        }
    }

    /// What happens on a double-click.
    fn setup() -> i32 {
        // The installed copy was opened (from its folder or a shortcut): show how it is doing.
        if install::running_installed() {
            match status(DEFAULT_PIPE) {
                Ok(text) => install::message_box(&text, false),
                Err(e) => install::message_box(&format!("EMS Agent is installed, but its service is not answering.\n\n{e:#}"), true),
            }
            return 0;
        }
        // Check the settings before asking for administrator rights, so a
        // missing address is explained instead of ending in a silent failure.
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(e) => {
                install::message_box(&format!("Could not start the installer: {e}"), true);
                return 1;
            }
        };
        let cfg = match config::discover_setup(None, None, &exe, install::installed_config()) {
            Ok((cfg, _)) => cfg,
            Err(e) => {
                install::message_box(&format!("{e:#}"), true);
                return 1;
            }
        };
        if install::is_admin() {
            return install_with_dialog();
        }
        // The privileged steps run in an elevated copy. This copy stays as the
        // signed-in user so that it can start the tray helper in their session.
        match install::run_elevated("install --from-setup") {
            Ok(code) if code == 0 || code == install::EXIT_NOT_CONNECTED as u32 => {
                install::start_tray_helper();
                let done = install::Installed { server_url: cfg.server_url, hostname: crate::core::computer_name(), org: cfg.org, connected: code == 0 };
                install::message_box(&done.summary(), !done.connected);
                0
            }
            // The elevated copy has already said what went wrong.
            Ok(_) => 1,
            Err(_) => {
                install::message_box("EMS Agent was not installed: administrator rights are needed.\n\nRun the installer again and choose Yes when Windows asks.", true);
                1
            }
        }
    }

    fn install_with_dialog() -> i32 {
        match install::install(None, None) {
            Ok(done) => {
                install::message_box(&done.summary(), !done.connected);
                0
            }
            Err(e) => {
                install::message_box(&format!("EMS Agent could not be installed.\n\n{e:#}"), true);
                1
            }
        }
    }

    /// Reached from "Installed apps" in Windows Settings.
    fn uninstall_with_dialog() -> i32 {
        if !install::is_admin() {
            return match install::relaunch_elevated("uninstall --gui") {
                Ok(()) => 0,
                Err(_) => {
                    install::message_box("EMS Agent was not removed: administrator rights are needed.", true);
                    1
                }
            };
        }
        match install::uninstall(true) {
            Ok(removed) => {
                let mut text = String::from("EMS Agent has been removed from this computer, and all site blocking it applied has been lifted.");
                for note in &removed.notes {
                    text.push_str(&format!("\n\nNote: {note}"));
                }
                install::message_box(&text, false);
                // Last, after the message box: the folder holds this running program.
                if let Some(dir) = &removed.leftover_dir {
                    install::remove_dir_after_exit(dir);
                }
                0
            }
            Err(e) => {
                install::message_box(&format!("EMS Agent could not be removed.\n\n{e:#}"), true);
                1
            }
        }
    }

    /// Asks the running service how it is doing, over the local pipe.
    fn status(pipe_name: &str) -> anyhow::Result<String> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (policy, status) = rt
            .block_on(async { tokio::time::timeout(std::time::Duration::from_secs(5), crate::pipe::query(pipe_name)).await })
            .map_err(|_| anyhow::anyhow!("the agent service did not answer"))?
            .context("the agent service is not running on this computer")?;
        let last = match status.last_sync_ms {
            Some(ms) => format!("{} s ago", ((crate::logger::now_ms() - ms) / 1000).max(0)),
            None => "not yet".into(),
        };
        Ok(format!(
            "organisation     {}\n\
             computer         {}\n\
             server           {}\n\
             reaching server  {}\n\
             last check-in    {}\n\
             waiting to send  {} record(s)\n\
             blocking         {}\n\
             blocked sites    {}\n\
             blacklist words  {}\n\
             on a blocked tab {}\n\
             check-in every   {} s\n\
             agent version    {}",
            if status.org.is_empty() { "not known yet" } else { status.org.as_str() },
            status.hostname,
            status.server,
            if status.connected { "yes" } else { "no" },
            last,
            status.pending,
            status.enforcement,
            policy.blocked.len(),
            policy.words.len(),
            match (policy.close_blocked_tabs, policy.notify_user) {
                (true, false) => "close it silently",
                (true, true) => "close it and show a notice",
                (false, true) => "leave it open and show a notice",
                (false, false) => "leave it open",
            },
            policy.upload_interval_s,
            status.version,
        ))
    }

    /// Foreground development run of the background part.
    fn run(args: &[String]) -> anyhow::Result<()> {
        let data_dir = PathBuf::from(opt(args, "--data-dir").context("--data-dir <dir> is required")?);
        let (enforce, policy_hive) = match opt(args, "--enforce") {
            None => (false, PolicyHive::User),
            Some("user") => (true, PolicyHive::User),
            Some("machine") => (true, PolicyHive::Machine),
            Some(other) => bail!("--enforce takes `user` or `machine`, not {other:?}"),
        };
        let ctx = Ctx {
            hosts_path: opt(args, "--hosts-file").map(PathBuf::from).unwrap_or_else(|| data_dir.join("hosts")),
            pipe_name: pipe_name(args, r"\\.\pipe\ems-agent-dev"),
            data_dir,
            enforce,
            policy_hive,
            launch_sessions: false,
            update: if flag(args, "--self-update") { UpdateMode::Process } else { UpdateMode::Off },
        };
        crate::logger::init(&ctx.log_path(), true);

        if let Some(server) = opt(args, "--server") {
            let cfg = AgentConfig { server_url: config::normalize_server_url(server)?, key: opt(args, "--key").map(str::to_string), org: None };
            cfg.save(&ctx.config_path())?;
        }

        let shared = crate::core::init(ctx)?;
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
        rt.block_on(async {
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let quitting = shared.clone();
            tokio::spawn(async move {
                // Ctrl+C, or an update that is waiting for this process to end.
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = quitting.quit.notified() => {}
                }
                let _ = stop_tx.send(true);
                // Keep the sender alive so receivers see the change rather than a closed channel.
                std::future::pending::<()>().await;
            });
            crate::core::run(shared, stop_rx).await;
        });
        Ok(())
    }
}
