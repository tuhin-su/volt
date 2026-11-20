use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "volt",
    author = "VOLT Security Team",
    version,
    about = "Volatile Observation & Logging Terminal — Sandboxed forensic evidence collection and audit environment",
    long_about = "VOLT provides an isolated, spoofed hardware environment for cyber operations with always-on recording of terminal commands, SSH, raw network packets, browser activity, and desktop screenshots into a tamper-evident hash-chained evidence vault."
)]
pub struct Cli {
    #[arg(short, long, global = true, help = "Enable verbose debug logging")]
    pub verbose: bool,

    #[arg(long, global = true, help = "Path to custom volt.toml configuration")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Initialize a new evidence case directory with operational mode")]
    Init {
        #[arg(short, long, help = "Unique case identifier (e.g. IR-2026-0042)")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt init IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(
            short,
            long,
            default_value = "Investigator",
            help = "Name/ID of operator"
        )]
        investigator: String,

        #[arg(
            short,
            long,
            default_value = "vm-virtualbox",
            help = "Hardware profile: vm-virtualbox | laptop-dell | desktop-hp"
        )]
        profile: String,

        #[arg(
            short,
            long,
            default_value = "forensics",
            help = "Operation mode: forensics | red-team | blue-team | malware"
        )]
        mode: String,

        #[arg(long, help = "Law enforcement / Security Agency name")]
        agency: Option<String>,

        #[arg(long, help = "Search warrant or formal legal authorization reference")]
        warrant: Option<String>,

        #[arg(long, help = "Physical/Digital evidence tracking tag ID")]
        evidence_id: Option<String>,
    },

    #[command(about = "Start an isolated VOLT session with always-on capture")]
    Start {
        #[arg(short, long, help = "Case identifier to launch into")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt start IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(short, long, help = "Override hardware profile template")]
        profile: Option<String>,
    },

    #[command(
        about = "Open a full interactive shell terminal into an active VOLT session (alias: exec, attach)",
        alias = "exec",
        alias = "attach"
    )]
    Join {
        #[arg(short, long, help = "Active case identifier")]
        case: Option<String>,

        #[arg(help = "Active case identifier (positional, e.g. 'volt join IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(long, help = "Optional command to run instead of interactive shell")]
        cmd: Option<String>,

        #[arg(long, help = "Custom label for this terminal stream")]
        label: Option<String>,
    },

    #[command(about = "Stop the active VOLT session and stop all capture daemons")]
    Stop {
        #[arg(short, long, help = "Case identifier")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt stop IR-2026-0042')")]
        case_pos: Option<String>,
    },

    #[command(about = "Seal the evidence vault and compute cryptographic hash chain")]
    Seal {
        #[arg(short, long, help = "Case identifier")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt seal IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(long, help = "Sign the evidence manifest with GPG")]
        sign: bool,

        #[arg(long, help = "GPG key ID or email to sign with")]
        gpg_key: Option<String>,
    },

    #[command(about = "Verify the integrity of a sealed case or exported bundle")]
    Verify {
        #[arg(help = "Path to case directory or .volt bundle")]
        target: Option<PathBuf>,

        #[arg(short, long, help = "Target case or bundle (flag option)")]
        case: Option<PathBuf>,
    },

    #[command(about = "Generate a court-admissible forensic & operational audit report")]
    Report {
        #[arg(short, long, help = "Case identifier to generate report for")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt report IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(
            short,
            long,
            default_value = "markdown",
            help = "Report format: markdown | html"
        )]
        format: String,

        #[arg(short, long, help = "Custom output path for report")]
        output: Option<PathBuf>,
    },

    #[command(about = "Show status of cases, active captures, and disk usage")]
    Status {
        #[arg(short, long, help = "Optional specific case identifier")]
        case: Option<String>,

        #[arg(help = "Optional case identifier (positional)")]
        case_pos: Option<String>,
    },

    #[command(about = "Take an immediate on-demand screenshot in the active case")]
    Screenshot {
        #[arg(short, long, help = "Case identifier")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt screenshot IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(short, long, help = "Optional label/tag for the screenshot")]
        label: Option<String>,
    },

    #[command(about = "Export a sealed case into a compressed evidence bundle")]
    Export {
        #[arg(short, long, help = "Case identifier")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt export IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(short, long, default_value = "volt", help = "Format: volt | targz")]
        format: String,

        #[arg(short, long, help = "Output destination file/directory")]
        output: Option<PathBuf>,
    },

    #[command(
        about = "Manage and inspect shared environment variables across terminal sessions",
        alias = "environment"
    )]
    Env {
        #[arg(short, long, help = "Case identifier")]
        case: Option<String>,

        #[arg(help = "Case identifier (positional, e.g. 'volt env IR-2026-0042')")]
        case_pos: Option<String>,

        #[arg(
            long,
            help = "Set a shared variable across all shells (e.g. --set KEY=VALUE)"
        )]
        set: Option<String>,

        #[arg(long, help = "Get the value of a shared variable (e.g. --get KEY)")]
        get: Option<String>,

        #[arg(
            long,
            help = "Unset a shared variable across all shells (e.g. --unset KEY)"
        )]
        unset: Option<String>,

        #[arg(long, help = "Clear all shared environment variables")]
        clear: bool,

        #[arg(long, help = "Output variables in JSON format")]
        json: bool,

        #[arg(long, help = "Output variables in shell export format")]
        export: bool,
    },
}
