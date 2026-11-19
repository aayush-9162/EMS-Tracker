//! Names and locations, and the runtime context that lets a development
//! run use its own directories instead of the installed ones.

use std::path::PathBuf;

pub const SERVICE_NAME: &str = "EMSAgent";
pub const DISPLAY_NAME: &str = "EMS Agent";
pub const SERVICE_DESCRIPTION: &str = "Records web and application activity for the organization and applies its site-blocking policy.";
pub const DEFAULT_PIPE: &str = r"\\.\pipe\ems-agent";
pub const RUN_VALUE: &str = "EMSAgent";
pub const EXE_NAME: &str = "ems-agent.exe";

/// `%ProgramData%\EMS`: configuration, upload queue and logs. Administrators only.
pub fn program_data() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into())).join("EMS")
}

/// `%ProgramFiles%\EMS Agent`: where the executable is installed.
pub fn install_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into())).join("EMS Agent")
}

pub fn system_hosts_file() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into())).join("System32\\drivers\\etc\\hosts")
}

/// Which registry hive browser policies are written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyHive {
    /// Machine-wide. What an installed agent uses.
    Machine,
    /// Current user only, for development runs. Windows protects this key
    /// too, so writing it still needs an elevated prompt.
    User,
}

/// How the agent replaces itself when the server holds a different program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateMode {
    /// Never. The default for a development run, so a build under test is not swapped out.
    Off,
    /// The installed agent: the Windows service is stopped, replaced and started again.
    Service,
    /// A development run asked to update itself: the process ends and is started again.
    Process,
}

/// Everything that differs between the installed service and a development run.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub data_dir: PathBuf,
    pub pipe_name: String,
    /// Apply the blocking policy to this machine (hosts file and browser policies).
    pub enforce: bool,
    pub hosts_path: PathBuf,
    pub policy_hive: PolicyHive,
    /// Start the tray helper in user sessions. Only the service can.
    pub launch_sessions: bool,
    pub update: UpdateMode,
}

impl Ctx {
    pub fn installed() -> Ctx {
        Ctx {
            data_dir: program_data(),
            pipe_name: DEFAULT_PIPE.into(),
            enforce: true,
            hosts_path: system_hosts_file(),
            policy_hive: PolicyHive::Machine,
            launch_sessions: true,
            update: UpdateMode::Service,
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("agent.json")
    }
    pub fn policy_path(&self) -> PathBuf {
        self.data_dir.join("policy.json")
    }
    /// Fingerprint of the inventory last uploaded, so an unchanged one is not sent again.
    pub fn inventory_hash_path(&self) -> PathBuf {
        self.data_dir.join("inventory.hash")
    }
    pub fn spool_dir(&self) -> PathBuf {
        self.data_dir.join("spool")
    }
    pub fn log_path(&self) -> PathBuf {
        self.data_dir.join("logs").join("agent.log")
    }
}
