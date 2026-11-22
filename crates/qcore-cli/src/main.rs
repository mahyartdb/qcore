//! qcore CLI: thin consumer of the core public API (FR-003a/003c). No GUI.
//!
//! stdout is results, stderr is diagnostics. `--json` emits exactly one JSON
//! document on stdout. `connect`/`up` validates a chain and brings up a
//! session (zero-config `up` = wireguard peer=warp, dual); `-d/--detach`
//! backgrounds via a re-spawned child plus the token-authenticated control
//! channel; `--bind` exposes a local SOCKS proxy through the exit hop.

pub mod cmd;
pub mod exit;
pub mod help;

use clap::{Parser, Subcommand};
use qcore_core::api::{Engine, EngineConfig};
use qcore_core::config::profile_dir::ProfileDirs;
use qcore_core::session::control;
use qcore_core::session::report::{self, ConnectionReport};
use qcore_core::session::{reconnect, Session, SessionLock, SessionState, SessionStatus};

#[derive(Parser)]
#[command(
    name = "qcore",
    version,
    about = "Multi-protocol tunnel client core CLI"
)]
struct Cli {
    /// Machine-readable output: exactly one JSON document on stdout.
    #[arg(long, short = 'j', global = true)]
    json: bool,

    /// Config dir override (identity, session, imports, secrets).
    #[arg(long, global = true)]
    config: Option<std::path::PathBuf>,

    /// Profile dir override (scan/obfuscation/composition data).
    #[arg(long = "profile-dir", global = true)]
    profile_dir: Option<std::path::PathBuf>,

    /// Chain depth cap (default 3, hard limit 5).
    #[arg(long = "max-depth", global = true)]
    max_depth: Option<u32>,

    /// Connection timeout seconds (default 30).
    #[arg(long, global = true, env = "CONNECTION_TIMEOUT_SECONDS")]
    timeout: Option<u64>,

    /// Disable color (output is never colorized; also honors NO_COLOR).
    #[arg(long, global = true)]
    no_color: bool,

    /// Suppress non-error diagnostics on stderr.
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Repeatable non-secret diagnostics (-v debug, -vv trace).
    #[arg(long, short = 'v', action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Never prompt; missing required values are exit 6.
    #[arg(long = "non-interactive", global = true)]
    non_interactive: bool,

    /// Confirm destructive actions off-TTY.
    #[arg(long, global = true)]
    yes: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Validated global options (T083).
struct GlobalOpts {
    max_depth: Option<u32>,
    timeout_secs: u64,
    quiet: bool,
    verbose: u8,
}

fn check_globals(cli: &Cli) -> Result<GlobalOpts, i32> {
    if let Some(d) = cli.max_depth {
        if !(1..=5).contains(&d) {
            exit::diag_exit(
                exit::USAGE,
                &format!("--max-depth {d} outside 1..=5 (hard limit 5)"),
            );
            return Err(exit::USAGE);
        }
    }
    let timeout_secs = cli.timeout.unwrap_or(30);
    // Same range the FFI clamps to (`qcore_engine_new`): an unrepresentable
    // budget would overflow the engine's deadline arithmetic.
    if !(1..=86_400).contains(&timeout_secs) {
        eprintln!("qcore: --timeout {timeout_secs} outside 1..=86400 seconds (exit 6)");
        return Err(exit::USAGE);
    }
    Ok(GlobalOpts {
        max_depth: cli.max_depth,
        timeout_secs,
        quiet: cli.quiet,
        verbose: cli.verbose,
    })
}

fn cli_dirs(cli: &Cli) -> ProfileDirs {
    ProfileDirs::resolve(cli.config.clone(), cli.profile_dir.clone())
}

/// Fail-safe bind policy (P1 hardening): `--bind` exposes an
/// UNAUTHENTICATED SOCKS5 proxy through the tunnel, so a non-loopback
/// listener is an open relay for the whole LAN unless the operator opted in
/// with `--expose-lan`. Pure decision fn so the policy is unit-testable.
fn bind_policy(addr: std::net::SocketAddr, expose_lan: bool) -> Result<(), &'static str> {
    if addr.ip().is_loopback() || expose_lan {
        return Ok(());
    }
    Err("refusing non-loopback --bind without --expose-lan")
}

/// The dirs a ConnectOpts carries (the double-start guard reads them before
/// anything else runs).
fn dirs_of(o: &ConnectOpts) -> &ProfileDirs {
    &o.globals_dirs
}

/// Mirror of `config::import::wireguard_family_winner` (private to the
/// core): only a cached *wireguard-family* winner may suppress discovery.
/// The legacy bare `last_known_good` carries no transport tag and can name a
/// masque/tor endpoint, so reading it here would skip discovery on a
/// cross-transport poisoning.
fn wireguard_family_winner_cached(dirs: &ProfileDirs, family: &str) -> bool {
    const WG_FAMILY_KEYS: &[&str] = &["wireguard", "warp"];
    qcore_core::scan::cache::read_winners(dirs)
        .into_iter()
        .filter(|(k, _)| WG_FAMILY_KEYS.contains(&k.as_str()))
        .filter(|(_, w)| family == "dual" || w.family == family)
        .max_by_key(|(_, w)| w.verified_at_ms)
        .and_then(|(_, w)| w.socket_addr())
        .is_some()
}

/// Double-start refusal: usage-class failure, emitted without touching
/// control.json or session.json. With `--json`, stdout still carries exactly
/// one failure document (the finish_connect_failure shape, reason included).
/// `blocker` is the core gate's actionable reason (names the id + remedy).
fn reject_already_running(json: bool, blocker: &str) -> i32 {
    let msg = blocker.to_string();
    exit::diag_exit(exit::USAGE, &msg);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": false,
                "layer": qcore_transport_api::FailureLayer::Config.to_string(),
                "hop_id": "",
                "kind": "usage",
                "reason": msg,
                "cause": msg,
            })
        );
    }
    exit::USAGE
}

/// One pre-start usage failure document (contracts/cli.md §1): with `--json`,
/// stdout carries exactly ONE document even when no hop ever started —
/// silence is a contract violation, not a rejection (the `ls --json`
/// precedent). Shape follows [`finish_connect_failure`] plus the actionable
/// `reason` the sibling usage paths emit; `cause`/`reason` pass the central
/// redactor (a secret-shaped flag value must not ride out) and no hop
/// started, so `hop_id` is empty. The caller keeps its stderr diagnostic and
/// exit code unchanged.
fn emit_prestart_usage_failure(json: bool, reason: &str) {
    if !json {
        return;
    }
    println!(
        "{}",
        serde_json::json!({
            "ok": false,
            "layer": qcore_transport_api::FailureLayer::Config.to_string(),
            "hop_id": "",
            "kind": "usage",
            "reason": qcore_core::diag::masked_value("reason", reason),
            "cause": qcore_core::diag::masked_value("cause", reason),
        })
    );
}

// The `Connect` variant is a clap arg container: built once at startup and
// never moved around, so the size heuristic's stack-movement premise does
// not apply. Boxing flags to shrink it would only obscure the CLI surface.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Commands {
    /// Validate a chain and bring up a session (alias: up).
    #[command(alias = "up")]
    Connect {
        /// Chain expression (full grammar: hop (, hop)*, presets, @labels).
        #[arg(long)]
        chain: Option<String>,
        /// TOML chain declaration file.
        #[arg(long)]
        chain_file: Option<String>,
        /// One hop (repeatable; argv order defines chain order).
        #[arg(long)]
        hop: Vec<String>,
        /// Positional chain.toml file.
        #[arg(index = 1)]
        file: Option<String>,
        /// Address family: ipv4 | ipv6 | dual.
        #[arg(long, short = 'f', default_value = "dual")]
        family: String,
        /// Happy Eyeballs preference: ipv4 | ipv6.
        #[arg(long, default_value = "ipv4")]
        prefer: String,
        /// Write the ConnectionReport JSON to this path.
        #[arg(long)]
        report_out: Option<String>,
        /// Diagnostic level: error | warn | info | debug | trace.
        #[arg(long, default_value = "info")]
        log_level: String,
        /// Background; writes session.json, status/stop via control channel.
        #[arg(long, short = 'd')]
        detach: bool,
        /// Local proxy listener through the exit hop (default 127.0.0.1:0).
        #[arg(long, num_args = 0..=1, default_missing_value = "127.0.0.1:0")]
        bind: Option<String>,
        /// Local HTTP CONNECT proxy listener (RFC 7231 §4.3.6) served next
        /// to `--bind` through the same exit hop: CONNECT only — plain-HTTP
        /// proxying answers 405. Same exposure policy as `--bind`:
        /// loopback-only unless `--expose-lan` (exit 6 otherwise).
        #[arg(long = "http-proxy")]
        http_proxy: Option<String>,
        /// Opt in to a non-loopback --bind listener. The proxy is an
        /// UNAUTHENTICATED SOCKS5 endpoint through the tunnel: a LAN bind
        /// lets every reachable peer use your exit. Refused without this
        /// flag (exit 6).
        #[arg(long)]
        expose_lan: bool,
        /// Disable endpoint discovery on connect (default on; scans once
        /// when the chain needs an endpoint and none is cached).
        #[arg(long)]
        no_scan: bool,
        /// Internal: detached child mode (spawned by --detach, not for users).
        #[arg(long, hide = true)]
        child: bool,
        /// Obfuscation profile chain-default (hops without explicit key inherit).
        #[arg(long = "obfuscation", short = 'O')]
        obfuscation: Option<String>,
        /// DNS resolver address for SOCKS5 domain targets, reachable from
        /// inside the tunnel (default: the WARP resolver 1.1.1.1; parse
        /// failure is exit 6).
        #[arg(long)]
        dns: Option<String>,
        /// Keepalive probe interval seconds, or `off` to disable the
        /// per-hop health watcher (default 25). The auto-reconnect watchdog
        /// only acts on failures it can observe, so `off` also disables
        /// in-place hop rebuilds.
        #[arg(long)]
        keepalive: Option<String>,
        /// Routing rules file (default: `<profile-dir>/routing.toml` when
        /// present). Rules match the CONNECT/UDP destination - domain
        /// suffix, CIDR, port - first match wins, action proxy|direct|block.
        /// Exception: a CIDR `block` is unorderable, it wins over any
        /// earlier rule when the resolved address matches. `direct` bypasses
        /// the tunnel; `block` refuses before any egress.
        #[arg(long)]
        routing: Option<String>,
    },
    /// Tear down the current session (alias: down).
    #[command(alias = "down")]
    Stop,
    /// Validate chain + profiles + config, open zero sockets (alias: check).
    #[command(alias = "check")]
    Preflight {
        #[arg(long)]
        chain: Option<String>,
        /// TOML chain declaration file.
        #[arg(long)]
        chain_file: Option<String>,
        /// One hop (repeatable; argv order defines chain order).
        #[arg(long)]
        hop: Vec<String>,
        /// Positional chain.toml file.
        #[arg(index = 1)]
        file: Option<String>,
        /// Obfuscation profile chain-default (hops without explicit key inherit).
        #[arg(long = "obfuscation", short = 'O')]
        obfuscation: Option<String>,
    },
    /// Print the current session report.
    Status,
    /// Engine + API + ABI + schema versions.
    Version,
    /// List transports, profiles, presets and shortcuts (alias: profiles).
    #[command(alias = "profiles")]
    Ls,
    /// Discover and traffic-validate endpoints (exit 4 when none reachable).
    Scan {
        /// Transport kind to scan for.
        #[arg(long)]
        transport: String,
        /// Scan profile: turbo | balanced | stealth.
        #[arg(long, default_value = "balanced")]
        profile: String,
        /// Address family: ipv4 | ipv6 | dual.
        #[arg(long, short = 'f', default_value = "dual")]
        family: String,
        /// Output shape: table | json | ndjson.
        #[arg(long, default_value = "table")]
        output: String,
    },
    /// Import a WireGuard/AmneziaWG config (rejection is exit 5).
    Import {
        /// Config file to import.
        #[arg(index = 1)]
        file: String,
    },
    /// Provision a WARP identity (license optional; --gool for outer+inner).
    Register {
        /// Provider license key for this operation only (warns: visible to
        /// other processes; prefer --license-file).
        #[arg(long)]
        license_key: Option<String>,
        /// Read the license key from this file (scripts).
        #[arg(long)]
        license_file: Option<std::path::PathBuf>,
        /// Provision the GOOL outer+inner pair.
        #[arg(long)]
        gool: bool,
        /// Test-only provider override (fixture doubles; never stable).
        #[arg(long, hide = true)]
        provider: Option<String>,
    },
    /// Refresh an identity in place (re-register on refusal; --masque-only
    /// rotates just the MASQUE credential; --hop selects a GOOL hop).
    Renew {
        /// Only the MASQUE credential (enroll when missing, rotate in-window).
        #[arg(long)]
        masque_only: bool,
        /// Which identity: outer | inner | both (default both).
        #[arg(long, default_value = "both")]
        hop: String,
        /// Provider license key for this operation only (warns: visible to
        /// other processes; prefer --license-file).
        #[arg(long)]
        license_key: Option<String>,
        /// Read the license key from this file (scripts).
        #[arg(long)]
        license_file: Option<std::path::PathBuf>,
        /// Test-only provider override (fixture doubles; never stable).
        #[arg(long, hide = true)]
        provider: Option<String>,
    },
    /// Round-trip an imported config (values reproduced, secrets redacted).
    Export {
        /// Import ref from `import`.
        #[arg(index = 1)]
        import_ref: String,
    },
    /// Lawful-use + jurisdiction statements (text or --json).
    Legal,
    /// Generated chain shortcut (e.g. `tor-warp`); unknown tokens exit 6.
    #[command(external_subcommand)]
    External(Vec<String>),
}

fn main() {
    #[cfg(windows)]
    use_utf8_console();
    // Reset SIGPIPE to SIG_DFL (the Rust runtime starts with it ignored).
    #[cfg(unix)]
    {
        // SAFETY: `signal` with SIG_DFL is a plain syscall; called before
        // any thread spawns, so POSIX's undefined concurrent-fn behavior
        // does not apply.
        unsafe {
            let _ = libc_sigpipe_default();
        }
    }
    // Force linkage of every enabled transport so inventory registration
    // reaches the engine registry (static archives only link used objects).
    let _ = qcore_transports::linked_kinds();
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => std::process::exit(clap_exit(&e)),
    };
    let code = run(cli);
    std::process::exit(code);
}

/// Map a clap parse failure to the contracted shape (contracts/cli.md §2):
/// `--help`/`--version` are results (stdout, exit 0); every other failure is
/// a usage error, reported as ONE `qcore: <msg> (exit 6)` diagnostic rather
/// than clap's multi-line block and its default exit 2.
fn clap_exit(err: &clap::Error) -> i32 {
    use clap::error::ErrorKind;
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let _ = err.print();
            exit::SUCCESS
        }
        // Bare `qcore` (no subcommand): clap renders the full help into the
        // error, but `err.print()` would put that help on STDERR (this kind's
        // stream). Help is a result, so it goes to stdout here, and stderr
        // carries the one usage diagnostic naming the miss.
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            println!("{}", err.render());
            exit::diag_exit(exit::USAGE, "no command given");
            exit::USAGE
        }
        _ => {
            exit::diag_exit(exit::USAGE, &collapsed_clap_message(err));
            exit::USAGE
        }
    }
}

/// Usage diagnostics are one line per failure; clap renders its message as an
/// error line, a usage block and a `--help` hint. Collapse the whitespace and
/// keep only the core message: `diag_exit` supplies the `qcore: ` framing, so
/// clap's own `error: ` prefix is redundant, and its usage block/help hint are
/// a trailer that would turn the one-line diagnostic into a run-on.
fn collapsed_clap_message(err: &clap::Error) -> String {
    let collapsed = err
        .to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let msg = collapsed.strip_prefix("error: ").unwrap_or(&collapsed);
    let msg = msg.split(" Usage: ").next().unwrap_or(msg);
    let msg = msg.split(" For more information").next().unwrap_or(msg);
    msg.trim().to_string()
}

/// Reset SIGPIPE to SIG_DFL (the Rust runtime starts with it ignored): a
/// closed stdout (e.g. `qcore ls | head`) must end the process like any Unix
/// filter, not panic on the first print. Declared locally to avoid a libc
/// dependency: `signal` is in every libc.
#[cfg(unix)]
unsafe fn libc_sigpipe_default() -> i32 {
    // ::signal(int, void (*)(int)) — SIGPIPE = 13, SIG_DFL = 0.
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    signal(13, 0) as i32
}

/// Windows consoles default to the OEM code page, so UTF-8 results (JSON
/// with non-ASCII names, text reports) arrive mojibake. Switch both the
/// input and output code pages to UTF-8 at startup. No `windows-sys`
/// dependency: these two kernel32 calls are stable ABI and failure (no
/// console, e.g. a detached child) is harmless.
#[cfg(windows)]
fn use_utf8_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleOutputCP(code_page: u32) -> i32;
        fn SetConsoleCP(code_page: u32) -> i32;
    }
    const CP_UTF8: u32 = 65001;
    // SAFETY: both calls only set this process's console state; a non-BOOL
    // return just means no console is attached.
    unsafe {
        let _ = SetConsoleOutputCP(CP_UTF8);
        let _ = SetConsoleCP(CP_UTF8);
    }
}

fn run(cli: Cli) -> i32 {
    // A current-thread runtime suffices: one session, few sockets.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> i32 {
    let globals = match check_globals(&cli) {
        Ok(g) => g,
        Err(code) => return code,
    };
    let dirs = cli_dirs(&cli);
    match cli.command {
        Commands::Version => {
            let (api, abi, schema) = Engine::versions();
            let target = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "engine": env!("CARGO_PKG_VERSION"),
                        "api": api,
                        "abi": abi,
                        "schema": schema,
                        "target": target,
                    })
                );
            } else {
                println!("qcore {}", env!("CARGO_PKG_VERSION"));
                println!("api {api}  abi {abi}  schema {schema}  target {target}");
            }
            exit::SUCCESS
        }
        Commands::Preflight {
            chain,
            chain_file,
            hop,
            file,
            obfuscation,
        } => {
            let engine = cmd::preflight::default_engine(dirs.clone());
            let mut inputs = match cmd::preflight::resolve_inputs(
                &engine,
                chain.as_deref(),
                chain_file.as_deref(),
                file.as_deref(),
                &hop,
            ) {
                Ok(i) => i,
                Err((code, msg)) => {
                    exit::diag_exit(code, &msg);
                    return code;
                }
            };
            if let Some(profile) = obfuscation.as_deref() {
                if cmd::preflight::apply_obfuscation_default(&mut inputs.specs, profile) == 0 {
                    return cmd::preflight::reject_obfuscation_without_target(profile, cli.json);
                }
            }
            cmd::preflight::run_resolved(&engine, &inputs, cli.json, globals.quiet)
        }
        Commands::Status => run_status(cli.json, &dirs),
        Commands::Stop => run_stop(cli.json, &dirs),
        Commands::Ls => {
            // `ls` is human-readable only: `--json` would silently violate
            // the one-document stdout contract, so fail closed (exit 6).
            if cli.json {
                eprintln!("qcore: ls --json not supported (exit 6)");
                return exit::USAGE;
            }
            let engine = cmd::preflight::default_engine(dirs.clone());
            cmd::profiles::run(&engine, &dirs)
        }
        Commands::Import { file } => cmd::import::run_import(&file, cli.json, &dirs, globals.quiet),
        Commands::Register {
            license_key,
            license_file,
            gool,
            provider,
        } => {
            cmd::register::run(cmd::register::RegisterArgs {
                license_key,
                license_file,
                gool,
                provider,
                json: cli.json,
                non_interactive: cli.non_interactive,
                dirs,
            })
            .await
        }
        Commands::Renew {
            masque_only,
            hop,
            license_key,
            license_file,
            provider,
        } => {
            cmd::renew::run(cmd::renew::RenewArgs {
                masque_only,
                hop,
                license_key,
                license_file,
                provider,
                json: cli.json,
                non_interactive: cli.non_interactive,
                dirs,
            })
            .await
        }
        Commands::Export { import_ref } => cmd::import::run_export(&import_ref, cli.json, &dirs),
        Commands::Legal => help::run(cli.json),
        Commands::External(args) => {
            run_shortcut(args, cli.json, dirs, cli.config, cli.profile_dir, &globals).await
        }
        Commands::Connect {
            chain,
            chain_file,
            hop,
            file,
            family,
            prefer,
            report_out,
            log_level,
            detach,
            bind,
            expose_lan,
            http_proxy,
            child,
            no_scan,
            obfuscation,
            dns,
            keepalive,
            routing,
        } => {
            // Discovery is default-on; `--no-scan` is the only switch (the
            // old `--scan` flag was declared `default_value_t = true` with
            // SetTrue, so it could never be false from argv and every
            // `--no-scan` hit the conflict guard: exit 6 always).
            run_connect(ConnectOpts {
                chain,
                chain_file,
                hop,
                file,
                family,
                prefer,
                report_out,
                log_level,
                detach,
                bind,
                expose_lan,
                http_proxy,
                child,
                scan: !no_scan,
                obfuscation,
                dns,
                keepalive,
                routing,
                globals_max_depth: globals.max_depth,
                globals_timeout: globals.timeout_secs,
                globals_quiet: globals.quiet,
                globals_verbose: cli.verbose,
                globals_dirs: dirs,
                globals_config: cli.config,
                globals_profile_dir: cli.profile_dir,
                json: cli.json,
                shortcut_specs: None,
                shortcut_expr: None,
            })
            .await
        }
        Commands::Scan {
            transport,
            profile,
            family,
            output,
        } => {
            cmd::scan::run(
                &transport,
                &profile,
                &family,
                &output,
                cli.json,
                globals.quiet,
                &dirs,
            )
            .await
        }
    }
}

struct ConnectOpts {
    chain: Option<String>,
    chain_file: Option<String>,
    hop: Vec<String>,
    file: Option<String>,
    family: String,
    prefer: String,
    report_out: Option<String>,
    log_level: String,
    detach: bool,
    bind: Option<String>,
    /// Explicit opt-in for a non-loopback `--bind` (see `bind_policy`).
    expose_lan: bool,
    /// Local HTTP CONNECT listener address (raw argv form; parsed in
    /// `run_connect`, exit 6 on failure). `None` = no HTTP listener.
    http_proxy: Option<String>,
    child: bool,
    /// Endpoint discovery on connect (scan once when needed).
    scan: bool,
    /// Obfuscation profile chain-default.
    obfuscation: Option<String>,
    /// Tunnel-side DNS resolver address for SOCKS5 domain targets
    /// (`None` = engine default resolution: WARP resolver for the
    /// warp/wireguard family). Raw argv form; parsed in `run_connect`
    /// (exit 6 on failure).
    dns: Option<String>,
    /// Keepalive argv form (`secs` | `off`); parsed in `run_connect`
    /// (exit 6 on failure). `None` = engine default (25 s, on).
    keepalive: Option<String>,
    /// Routing rules path (argv form; loaded in `run_connect` before the
    /// detach re-spawn). `None` = `<profile-dir>/routing.toml` when present.
    routing: Option<String>,
    /// Validated globals (T083).
    globals_max_depth: Option<u32>,
    globals_timeout: u64,
    globals_quiet: bool,
    globals_verbose: u8,
    globals_dirs: ProfileDirs,
    globals_config: Option<std::path::PathBuf>,
    globals_profile_dir: Option<std::path::PathBuf>,
    json: bool,
    /// Pre-resolved shortcut specs (rule 4: identical downstream path).
    shortcut_specs: Option<Vec<qcore_core::chain::ExpandedHop>>,
    /// Canonical expression for detach child re-spawn.
    shortcut_expr: Option<String>,
}

/// Shortcut dispatch (T057): pure alias into the connect flow.
async fn run_shortcut(
    args: Vec<String>,
    json: bool,
    dirs: ProfileDirs,
    config: Option<std::path::PathBuf>,
    profile_dir: Option<std::path::PathBuf>,
    globals: &GlobalOpts,
) -> i32 {
    let engine = cmd::preflight::default_engine(dirs.clone());
    let presets = match qcore_core::chain::preset::resolve_presets(&dirs) {
        Ok(p) => p,
        Err(e) => {
            // Shortcut dispatch runs before any chain input exists, so an
            // unreadable/unparseable compositions.toml is an environment
            // (config-read) failure, not an invalid authored chain. The
            // documented table has no dedicated config-read class; usage
            // (exit 6) is the agreed mapping — the operator must fix the
            // file, the same remedy as any other refused invocation.
            exit::diag_exit(
                exit::USAGE,
                &format!("cannot load composition presets: {e}"),
            );
            return exit::USAGE;
        }
    };
    let name = args.join(" ");
    // Shortcuts honor validated globals like --chain does (max-depth
    // validated 1..=5 in check_globals); default 3 matches connect.
    let max_depth = globals.max_depth.unwrap_or(3);
    match cmd::shortcuts::resolve(
        &engine,
        &presets,
        max_depth,
        args.first().map(|s| s.as_str()).unwrap_or(""),
    ) {
        Ok(specs) => {
            if args.len() != 1 {
                eprintln!("qcore: shortcut `{name}` takes no operands (exit 6)");
                return exit::USAGE;
            }
            let expr = cmd::shortcuts::canonical_expr(&specs);
            run_connect(ConnectOpts {
                chain: None,
                chain_file: None,
                hop: vec![],
                file: None,
                family: "dual".into(),
                prefer: "ipv4".into(),
                report_out: None,
                log_level: "info".into(),
                detach: false,
                bind: None,
                http_proxy: None,
                // Shortcuts never bind a LAN proxy; --expose-lan has no
                // surface here (flags after a shortcut token are operands,
                // exit 6 per grammar).
                expose_lan: false,
                child: false,
                // Match `connect` default: discovery on unless --no-scan.
                scan: true,
                obfuscation: None,
                dns: None,
                keepalive: None,
                // Shortcut tokens take no flags: the profile-dir default
                // applies, exactly like `connect` without `--routing`.
                routing: None,
                globals_max_depth: Some(max_depth),
                globals_timeout: globals.timeout_secs,
                globals_quiet: globals.quiet,
                globals_verbose: globals.verbose,
                globals_dirs: dirs.clone(),
                globals_config: config,
                globals_profile_dir: profile_dir,
                json,
                shortcut_specs: Some(specs),
                shortcut_expr: Some(expr),
            })
            .await
        }
        Err(cmd::shortcuts::ResolveFailure::Unknown(_)) => {
            eprintln!("qcore: unknown command or shortcut `{name}` (exit 6)");
            exit::USAGE
        }
        Err(cmd::shortcuts::ResolveFailure::Invalid(e)) => {
            // This failure comes from authoring/validation of the expanded
            // chain (depth cap, parse) — a genuine invalid-chain verdict
            // (exit 2), not a config-read problem.
            eprintln!("qcore: invalid chain (exit 2)\n  {e}");
            exit::INVALID
        }
    }
}

fn check_level(level: &str) -> Result<u8, String> {
    match level {
        "error" => Ok(0),
        "warn" => Ok(1),
        "info" => Ok(2),
        "debug" => Ok(3),
        "trace" => Ok(4),
        _ => Err(format!(
            "invalid --log-level `{level}` (expected error|warn|info|debug|trace)"
        )),
    }
}

async fn run_connect(o: ConnectOpts) -> i32 {
    // Double-start guard (P1): consult the core start gate
    // (`SessionStatus::assert_startable`, wave C2) BEFORE touching
    // control.json or session.json — a Live-looking/Unverifiable record
    // means another session may still own the control channel. The gate
    // opens zero sockets; its actionable reason names the blocking id and
    // the command that clears it.
    if let Err(blocker) = SessionStatus::assert_startable(dirs_of(&o)) {
        return reject_already_running(o.json, blocker.reason.as_str());
    }

    // -v bumps the effective level when --log-level is at its default.
    let log_level = if o.globals_verbose > 0 && o.log_level == "info" {
        if o.globals_verbose > 1 {
            "trace"
        } else {
            "debug"
        }
        .to_string()
    } else {
        o.log_level.clone()
    };
    let _verbose = match check_level(&log_level) {
        Ok(v) => v,
        Err(msg) => {
            exit::diag_exit(exit::USAGE, &msg);
            emit_prestart_usage_failure(o.json, &msg);
            return exit::USAGE;
        }
    };
    let dirs = o.globals_dirs.clone();
    // Fail fast on family/prefer before touching the network (exit 6:
    // unknown families are usage errors, matching `scan --family`).
    if let Err(e) = qcore_core::session::net::FamilyPolicy::parse(&o.family, &o.prefer) {
        eprintln!("qcore: {e} (exit 6)");
        emit_prestart_usage_failure(o.json, &e);
        return exit::USAGE;
    }
    let bind_addr: Option<std::net::SocketAddr> = match o.bind {
        Some(ref b) => match b.parse() {
            Ok(a) => Some(a),
            Err(_) => {
                let msg = format!("invalid --bind `{b}` (expected host:port)");
                exit::diag_exit(exit::USAGE, &msg);
                emit_prestart_usage_failure(o.json, &msg);
                return exit::USAGE;
            }
        },
        None => None,
    };
    // Non-loopback --bind is an unauthenticated open proxy on the LAN:
    // refuse unless --expose-lan opted in (fail-safe default, exit 6).
    if let Some(addr) = bind_addr {
        if let Err(msg) = bind_policy(addr, o.expose_lan) {
            exit::diag_exit(exit::USAGE, msg);
            emit_prestart_usage_failure(o.json, msg);
            return exit::USAGE;
        }
    }

    // --http-proxy parses and gates exactly like --bind: a malformed
    // address is a usage error (exit 6), and a non-loopback listener is the
    // same unauthenticated open relay, so bind_policy applies unchanged.
    // Parsing happens before the detach re-spawn so a bad value never
    // spawns a child.
    let http_proxy_addr: Option<std::net::SocketAddr> = match o.http_proxy {
        Some(ref h) => match h.parse() {
            Ok(a) => Some(a),
            Err(_) => {
                let msg = format!("invalid --http-proxy `{h}` (expected host:port)");
                exit::diag_exit(exit::USAGE, &msg);
                emit_prestart_usage_failure(o.json, &msg);
                return exit::USAGE;
            }
        },
        None => None,
    };
    if let Some(addr) = http_proxy_addr {
        if bind_policy(addr, o.expose_lan).is_err() {
            let msg = "refusing non-loopback --http-proxy without --expose-lan";
            exit::diag_exit(exit::USAGE, msg);
            emit_prestart_usage_failure(o.json, msg);
            return exit::USAGE;
        }
    }

    // Tunnel-side DNS resolver for SOCKS5 domain targets: explicit --dns
    // wins; otherwise the WARP resolver (the documented resolver of the
    // warp/wireguard exit family, reachable only from inside the tunnel).
    // A malformed address is a usage error (exit 6), like --bind. Parsing
    // happens before the detach re-spawn so a bad value never spawns a child.
    let dns_resolver = match &o.dns {
        Some(raw) => match raw.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                let msg = format!("invalid --dns `{raw}` (expected an IP address)");
                exit::diag_exit(exit::USAGE, &msg);
                emit_prestart_usage_failure(o.json, &msg);
                return exit::USAGE;
            }
        },
        None => Some(qcore_core::session::resolver::DEFAULT_DNS_RESOLVER),
    };

    // Keepalive policy (F2): `secs` sets the watcher interval, `off`
    // disables the watcher (and with it the auto-reconnect watchdog — it
    // only acts on failures it can observe). Usage error (exit 6) like the
    // other malformed value flags; parsed before the detach re-spawn.
    let keepalive_secs = match &o.keepalive {
        Some(raw) => match qcore_core::session::net::KeepalivePolicy::parse(raw) {
            Ok(parsed) => parsed,
            Err(e) => {
                exit::diag_exit(exit::USAGE, &e);
                emit_prestart_usage_failure(o.json, &e);
                return exit::USAGE;
            }
        },
        None => Some(qcore_core::session::net::ADVISORY_KEEPALIVE_SECS),
    };
    let keepalive = qcore_core::session::net::KeepalivePolicy {
        enabled: keepalive_secs.is_some(),
        interval_secs: keepalive_secs.unwrap_or(qcore_core::session::net::ADVISORY_KEEPALIVE_SECS),
    };

    // Routing rules (`routing.toml`): an explicit --routing wins (a missing
    // or unparseable file is a usage error, exit 6, naming the file and the
    // failing field); otherwise the profile-dir default applies when
    // present, and absent means the historic all-proxy path. Loaded before
    // the detach re-spawn so a bad file never spawns a child.
    let (router, routing_from) = match &o.routing {
        Some(raw) => {
            let path = std::path::Path::new(raw);
            match qcore_core::session::routing::Router::load(path) {
                Ok(r) => (r, Some(path.to_path_buf())),
                Err(e) => {
                    let msg = format!("invalid routing rules: {e}");
                    exit::diag_exit(exit::USAGE, &msg);
                    emit_prestart_usage_failure(o.json, &msg);
                    return exit::USAGE;
                }
            }
        }
        None => {
            let path = dirs
                .profile_dir
                .join(qcore_core::config::routing::ROUTING_FILE);
            match qcore_core::session::routing::Router::load_optional(&dirs) {
                Ok(r) if r.is_empty() => (r, None),
                Ok(r) => (r, Some(path)),
                Err(e) => {
                    let msg = format!("invalid routing rules: {e}");
                    exit::diag_exit(exit::USAGE, &msg);
                    emit_prestart_usage_failure(o.json, &msg);
                    return exit::USAGE;
                }
            }
        }
    };
    let router = std::sync::Arc::new(router);

    // Detached parent: re-spawn self as the session process, wait for UP.
    if o.detach && !o.child {
        return spawn_detached(o).await;
    }

    // Active routing is announced once: a `direct` or `block` rule means
    // some traffic does NOT ride the tunnel, and the operator must see that
    // from the session output (stderr; the report schema is stable).
    if let Some(path) = &routing_from {
        eprintln!(
            "qcore: routing active: {} rule(s) from {} (non-matching targets proxy through the tunnel)",
            router.len(),
            path.display()
        );
    }

    // Session ownership lock (H2.5): taken by the process that actually
    // becomes the session (foreground connect or the detached CHILD, never
    // the detach parent) before the first durable write, and held until the
    // session stops. Closes the startup window where session.json does not
    // exist yet but two connects could both pass `assert_startable`.
    let session_lock = match SessionLock::acquire(&dirs) {
        Ok(lock) => lock,
        Err(e) => {
            exit::diag_exit(exit::USAGE, &e);
            emit_prestart_usage_failure(o.json, &e);
            return exit::USAGE;
        }
    };

    // Cold start (T048): identity first, then chain inputs (zero-config
    // default when nothing was given).
    if let Err(e) = reconnect::ensure_identity(&dirs) {
        exit::diag_exit(exit::HOP_FAILURE, &format!("identity unavailable: {e}"));
        return exit::HOP_FAILURE;
    }
    let (mut specs, file_depth) = match o.shortcut_specs {
        Some(s) => (s, None),
        None => {
            // A provisional engine resolves expressions (presets come from dirs).
            let probe = Engine::new(EngineConfig {
                dirs: dirs.clone(),
                family: o.family.clone(),
                prefer: o.prefer.clone(),
                ..Default::default()
            });
            let no_inputs =
                o.chain.is_none() && o.chain_file.is_none() && o.file.is_none() && o.hop.is_empty();
            if no_inputs {
                (reconnect::default_chain_spec(), None)
            } else {
                match cmd::preflight::resolve_inputs(
                    &probe,
                    o.chain.as_deref(),
                    o.chain_file.as_deref(),
                    o.file.as_deref(),
                    &o.hop,
                ) {
                    Ok(i) => (i.specs, i.max_depth),
                    Err((code, msg)) => {
                        // With --json, stdout carries exactly one failure
                        // document even when no hop ever started (contracts
                        // §1): the finish_connect_failure shape, with the
                        // masked cause (a secret-shaped reason degrades to a
                        // placeholder) and the reason for usage-class
                        // conflicts. The diagnostic still goes to stderr.
                        if o.json {
                            let (layer, kind) = if code == exit::INVALID {
                                (
                                    qcore_transport_api::FailureLayer::Validation.to_string(),
                                    "validation",
                                )
                            } else {
                                // Usage-class siblings (reject_already_running)
                                // report Config + "usage": no hop was built.
                                (
                                    qcore_transport_api::FailureLayer::Config.to_string(),
                                    "usage",
                                )
                            };
                            let cause = if code == exit::INVALID {
                                qcore_core::diag::masked_value("cause", &msg)
                            } else {
                                msg.clone()
                            };
                            println!(
                                "{}",
                                serde_json::json!({
                                    "ok": false,
                                    "layer": layer,
                                    "hop_id": "",
                                    "kind": kind,
                                    "reason": msg,
                                    "cause": cause,
                                })
                            );
                        }
                        if code == exit::INVALID {
                            // Same shape as the sibling invalid-chain sites
                            // (shortcut dispatch, obfuscation refusal): the
                            // `(exit N)` suffix rides the header line, the
                            // reason is an indented detail line below it.
                            eprintln!("qcore: invalid chain (exit {code})\n  {msg}");
                        } else {
                            exit::diag_exit(code, &msg);
                        }
                        return code;
                    }
                }
            }
        }
    };
    let engine = Engine::new(EngineConfig {
        dirs: dirs.clone(),
        family: o.family.clone(),
        prefer: o.prefer.clone(),
        // Explicit --max-depth wins over the chain file; default 3.
        max_depth: o.globals_max_depth.or(file_depth).unwrap_or(3),
        timeout_secs: o.globals_timeout,
        dns_resolver,
        keepalive,
    });

    // Detached child rendezvous comes UP FIRST: the control listener binds
    // and control.json is written before the (potentially slow) identity
    // provider round-trip, so the --detach parent polls a real liveness
    // signal from the first second instead of a fixed 10 s blind budget.
    // The shared report starts in the starting shape and is swapped for the
    // live one once hops are up; the token is minted here and reused.
    let starting_report = ConnectionReport::new(Vec::new(), STARTING_EXIT_MARKER);
    let shared_report = std::sync::Arc::new(tokio::sync::RwLock::new(starting_report));
    let (control_listener, token, early_rendezvous) = if o.child {
        match bind_early_rendezvous(&dirs, &session_lock).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("qcore: {e}");
                return exit::HOP_FAILURE;
            }
        }
    } else {
        (None, control::new_token(), false)
    };

    // Provider identities (002 FR-003/004/005): reuse healthy stored
    // identities, auto-register when none is stored, refresh-or-reregister
    // once on refusal, rotate in-window MASQUE credentials. Fail-closed
    // (exit 3: contracts/cli.md §2 maps connect-side hop failures to hop
    // failure, never to the invalid-chain code) when the provider is
    // unreachable or refuses.
    let id_opts = qcore_core::identity::register::ProviderOptions {
        provider_base: qcore_core::identity::register::DEFAULT_PROVIDER_BASE.to_string(),
        timeout_secs: 20,
        family: o.family.clone(),
    };
    match engine.preconnect_identity(&specs, &id_opts, None).await {
        Ok(Some(notice)) => {
            if !o.globals_quiet {
                eprintln!("qcore: {notice}");
            }
        }
        Ok(None) => {}
        Err(r) => {
            let fail = || {
                qcore_transport_api::FailureReport::new(
                    qcore_transport_api::FailureLayer::Sidecar,
                    "",
                    r.cause.clone(),
                    "identity",
                )
            };
            return finish_connect_failure(o.json, fail, early_rendezvous, &dirs);
        }
    }

    // Obfuscation chain-default (US5 T073 `-O`): hops without an explicit
    // `obfuscation=` key inherit the profile; validation names mismatches.
    if let Some(profile) = o.obfuscation.as_deref() {
        if cmd::preflight::apply_obfuscation_default(&mut specs, profile) == 0 {
            return cmd::preflight::reject_obfuscation_without_target(profile, o.json);
        }
    }

    // Scan-once discovery (US4 T068): when enabled and no verified endpoint
    // is cached and the chain may need one (a wireguard hop without endpoint
    // or any preset with an unknown exit), run one balanced scan and cache
    // the winner. Empty discovery is not fatal here — validation stays the
    // gate and fails closed (exit 2) when an endpoint is truly missing.
    let mut discovery_ran = false;
    if o.scan && !wireguard_family_winner_cached(&dirs, &o.family) {
        let needs_discovery = specs.iter().any(|s| match s {
            qcore_core::chain::ExpandedHop::Preset(_) => true,
            qcore_core::chain::ExpandedHop::Hop(h) => {
                matches!(
                    &h.config,
                    qcore_core::config::HopConfig::Wireguard(c)
                        if c.endpoint.is_none() && c.import_ref.is_none()
                )
            }
        });
        if needs_discovery {
            let transport = specs
                .iter()
                .rev()
                .find_map(|s| match s {
                    qcore_core::chain::ExpandedHop::Hop(h) => Some(h.config.kind().to_string()),
                    qcore_core::chain::ExpandedHop::Preset(_) => None,
                })
                .unwrap_or_else(|| "wireguard".to_string());
            // Zero-config default (002 FR-014): warp.toml's scan choice.
            let default_profile = qcore_core::session::reconnect::default_scan_profile(&dirs);
            match qcore_core::scan::load_profile(&dirs, &default_profile) {
                Ok(profile) => {
                    match cmd::scan::run_scan_request(&dirs, &transport, profile, &o.family).await {
                        Ok(report) if !report.ranked.is_empty() => {
                            if !o.globals_quiet {
                                eprintln!(
                                    "qcore: discovery cached {} ({} verified)",
                                    report.ranked[0].address,
                                    report.ranked.len()
                                );
                            }
                            discovery_ran = true;
                        }
                        _ => {
                            if !o.globals_quiet {
                                eprintln!(
                                    "qcore: discovery found nothing; continuing to validation"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    if !o.globals_quiet {
                        eprintln!("qcore: discovery skipped: {e}");
                    }
                }
            }
        }
    }

    // Bind --bind first: a taken port fails before any hop starts.
    let bind_listener = match bind_addr {
        Some(addr) => match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => Some(l),
            Err(e) => {
                // Pre-start failure, not a hop failure: no hop has started,
                // so the usage code (6) matches --bind syntax/policy above
                // (contracts/cli.md §4, proxy surface row).
                eprintln!("qcore: --bind {addr} unavailable: {e} (exit 6)");
                return exit::USAGE;
            }
        },
        None => None,
    };
    // The HTTP CONNECT listener binds beside the SOCKS one, before any hop
    // starts, under the same pre-start semantics.
    let http_listener = match http_proxy_addr {
        Some(addr) => match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => Some(l),
            Err(e) => {
                eprintln!("qcore: --http-proxy {addr} unavailable: {e} (exit 6)");
                return exit::USAGE;
            }
        },
        None => None,
    };

    let handle = match engine.start(specs).await {
        Ok(h) => h,
        Err(r) => {
            let fail = || r.clone();
            return finish_connect_failure(o.json, fail, early_rendezvous, &dirs);
        }
    };
    // The lock's authority is its token; the engine-assigned id is
    // diagnostic (the next starter's blocker names it). A failed rewrite
    // does not weaken the lock.
    if let Err(e) = session_lock.attach_session_id(&handle.id) {
        if !o.globals_quiet {
            eprintln!("qcore: {e} (continuing)");
        }
    }
    let mut report = ConnectionReport::new(handle.hop_reports(), handle.exit_hop_id.clone());
    // A proxy is bound iff either listener survived the bind gate (captured
    // before the listeners move into their serve tasks).
    let proxy_bound = bind_listener.is_some() || http_listener.is_some();
    // Active profiles in the report (T068 scan / T073 obfuscation): the exit
    // hop's obfuscation, and the scan profile when discovery ran.
    report.active_obfuscation = report
        .ordered_chain
        .iter()
        .rev()
        .find_map(|h| h.obfuscation.clone());
    if discovery_ran {
        report.active_scan_profile =
            Some(qcore_core::session::reconnect::default_scan_profile(&dirs));
    }
    // Relay byte counters (S3.1): the live report slot's sole writer is this
    // CLI, so populating here is the only surface for status over the
    // control channel. Counters advance live as relays move bytes (the
    // status-refresh loop below keeps the slot current after this snapshot).
    if proxy_bound {
        let (rx, tx) = qcore_core::session::proxy::relay_byte_totals();
        if rx > 0 || tx > 0 {
            report.bytes_in = Some(rx);
            report.bytes_out = Some(tx);
        }
    }
    // Publish the shared report slot onto the handle (R1.5): the watchdog's
    // publish_report writes degrade/reconnect fields into it, so STATUS over
    // the control channel shows session_state:"degraded" during a rebuild
    // instead of serving the stale start shape forever. Shared-state attach:
    // reaches the watchdog even though it holds earlier handle clones.
    handle.set_live_report(shared_report.clone());

    // Rendezvous for status/stop: durable records. The listener + control
    // file already exist for detached children (bound before identity); a
    // foreground connect binds them here as before.
    let (control_listener, token) = if early_rendezvous {
        let listener = control_listener.expect("early rendezvous binds the listener");
        (Some(listener), token)
    } else {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(e) => {
                let _ = handle.stop_all().await;
                eprintln!("qcore: control channel unavailable: {e}");
                return exit::HOP_FAILURE;
            }
        };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let token = control::new_token();
        match control::write_control_file(
            &dirs,
            &control::ControlInfo {
                port,
                token: token.clone(),
                pid: std::process::id(),
            },
        ) {
            Ok(()) => {}
            // FIX: a session whose rendezvous file cannot be written is
            // permanently unmanageable (stop/status forever unverifiable).
            // Fail closed here instead of `.ok()`-swallowing: tear the hops
            // down, clean best-effort, exit 3 naming the file.
            Err(e) => {
                let _ = handle.stop_all().await;
                let _ = std::fs::remove_file(control::control_file(&dirs));
                eprintln!(
                    "qcore: cannot write control file {}: {e} (exit 3)",
                    control::control_file(&dirs).display()
                );
                return exit::HOP_FAILURE;
            }
        }
        (Some(listener), token)
    };
    let mut session = Session {
        id: handle.id.clone(),
        chain: handle.chain.clone(),
        family_policy: qcore_core::session::net::FamilyPolicy::parse(&o.family, &o.prefer)
            .expect("validated above"),
        state: SessionState::Validating,
        started_at: now_ms(),
        failure: None,
        // The watchdog mutates this through its own record reads/writes.
        reconnects: 0,
    };
    let _ = session.transition(SessionState::Starting);
    let _ = session.transition(SessionState::Up);
    if session.save(&dirs).is_err() {
        let _ = handle.stop_all().await;
        exit::diag_exit(exit::HOP_FAILURE, "cannot write session state");
        return exit::HOP_FAILURE;
    }
    if let Some(path) = o.report_out.as_deref() {
        if std::fs::write(path, report::to_json(&report)).is_err() {
            eprintln!("qcore: cannot write --report-out `{path}`");
        }
    }
    // Publish the live report to the control channel (detached children
    // have been serving the starting shape until this swap) and emit it
    // once: stdout carries exactly one result document.
    *shared_report.write().await = report.clone();
    report::emit_report(&report, o.json);

    let listener = control_listener.expect("control listener bound above");
    // Peer policy mirrors the bind gate: loopback binds serve loopback
    // peers only; the explicit `--expose-lan` opt-in (which the bind gate
    // required for a non-loopback bind) also opts the peer filter out —
    // otherwise a LAN bind would refuse every LAN peer at accept time and
    // the flag would be a no-op (R1.4). Both proxy listeners share it.
    let peers = if o.expose_lan {
        qcore_core::session::proxy::PeerPolicy::Any
    } else {
        qcore_core::session::proxy::PeerPolicy::LoopbackOnly
    };
    if let Some(binder) = bind_listener {
        let bound = binder
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        eprintln!(
            "qcore: proxy listening on {bound} (via hop {})",
            handle.exit_hop_id
        );
        // Per-connection egress read (R1.1): the serve loop captures ONE
        // dialer for its lifetime, so it must be the live adapter — every
        // dial delegates to the handle's CURRENT exit, and after a watchdog
        // rebuild new connections dial the new chain without the CLI
        // knowing about rebuilds. The resolver rides the same live dialer
        // (its stored `Arc<dyn Dialer>` would otherwise pin the dead
        // pre-rebuild exit for ATYP=domain targets).
        tokio::spawn(
            qcore_core::session::proxy::serve_socks_via_dialer_with_routing(
                binder,
                handle.live_dialer(),
                // The session policy (not dual-default): `--family ipv4` refuses
                // IPv6 CONNECT with 0x08 at the SOCKS layer instead of dialing.
                session.family_policy.clone(),
                peers,
                // Tunnel-routed DNS for ATYP=domain targets over the LIVE
                // egress; None keeps the fail-closed refusal (no OS
                // resolver fallback).
                dns_resolver
                    .filter(|_| handle.dialer().capabilities().dials_udp)
                    .map(|ip| {
                        std::sync::Arc::new(qcore_core::session::resolver::TunnelResolver::new(
                            handle.live_dialer(),
                            ip,
                        ))
                    }),
                router.clone(),
            ),
        );
    }
    if let Some(http_binder) = http_listener {
        let bound = http_binder
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        eprintln!(
            "qcore: http proxy listening on {bound} (via hop {}, CONNECT only)",
            handle.exit_hop_id
        );
        // Same services + peer policy as the SOCKS listener (the resolver
        // rides the same live dialer and UDP-egress gate; see the SOCKS
        // block above for the rebuild semantics).
        tokio::spawn(qcore_core::session::proxy::serve_http_proxy_with_routing(
            http_binder,
            handle.live_dialer(),
            session.family_policy.clone(),
            peers,
            dns_resolver
                .filter(|_| handle.dialer().capabilities().dials_udp)
                .map(|ip| {
                    std::sync::Arc::new(qcore_core::session::resolver::TunnelResolver::new(
                        handle.live_dialer(),
                        ip,
                    ))
                }),
            router.clone(),
        ));
    }

    // Serve control until STOP or Ctrl-C or the watchdog gives up, then
    // tear down. Detached children have been serving since before identity;
    // the accept loop is owned here from now on either way. The status slot
    // refreshes on a loop: relay byte counters move continuously, and a
    // start-snapshot slot would serve zeros forever. The loop watches the
    // SLOT (dropped with the control serve task) for shutdown instead of
    // owning the stop sender.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let status_slot = shared_report.clone();
    let status_proxy_bound = proxy_bound;
    let status_refresh = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(2));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if !status_proxy_bound {
                continue;
            }
            let (rx, tx) = qcore_core::session::proxy::relay_byte_totals();
            let mut fresh = status_slot.read().await.clone();
            if rx > 0 || tx > 0 {
                fresh.bytes_in = Some(rx);
                fresh.bytes_out = Some(tx);
            }
            *status_slot.write().await = fresh;
        }
    });
    tokio::spawn(control::serve_control_shared(
        listener,
        token,
        shared_report.clone(),
        stop_tx,
    ));
    let mut give_up_rx = (*handle.give_up).clone();
    tokio::select! {
        _ = stop_rx => eprintln!("qcore: stop requested"),
        _ = tokio::signal::ctrl_c() => eprintln!("qcore: interrupted"),
        // Watchdog give-up (R1.6): the session went terminal-Failed on its
        // own (reconnect budget exhausted / flap cap). Idling here would
        // hold session.lock with session.json=Failed and let a later start
        // steal the live lock after the stale window — exit the process
        // with the failure report (connect exit 3 semantics: the session
        // Failed, the foreground/detached process must exit).
        gave_up = give_up_rx.wait_for(|fired| *fired) => {
            let _ = gave_up;
            // The failure detail was published into the shared report slot
            // (watchdog terminal path) before the signal fired.
            let failure = shared_report
                .read()
                .await
                .failure
                .clone()
                .unwrap_or_else(|| {
                    qcore_transport_api::FailureReport::new(
                        qcore_transport_api::FailureLayer::Transport,
                        "-",
                        "session gave up; reconnect budget exhausted",
                        "reconnect-budget",
                    )
                });
            eprintln!("qcore: session failed and could not be recovered");
            let _ = handle.stop_all().await;
            status_refresh.abort();
            control::remove_control_file(&dirs);
            // The record is already Failed (watchdog wrote it); release the
            // lock so the next start is not blocked by a dead holder.
            drop(session_lock);
            drop(session);
            return report::emit_failure(&failure);
        }
    }
    let _ = handle.stop_all().await;
    status_refresh.abort();
    session.state = SessionState::Stopped;
    if let Err(e) = session.save(&dirs) {
        // The tunnel is already down; a failed record write must not turn a
        // successful stop into a failure (the next `status` re-probes and
        // converges), but it must not be silent either. Informational note,
        // not the `(exit N)` failure shape: the stop still exits 0.
        eprintln!("qcore: note: session record save failed (stop succeeded): {e}");
    }
    control::remove_control_file(&dirs);
    // Clean stop releases ownership only after the durable record landed.
    drop(session_lock);
    exit::SUCCESS
}

/// The starting report's marker exit id: distinguishable from any real hop
/// (`hop_id`s are non-empty), so the --detach parent can tell "alive, still
/// starting" from "UP".
const STARTING_EXIT_MARKER: &str = "<starting>";

/// Bind the detached child's control listener + write control.json before
/// the identity round-trip (liveness for the --detach parent). Returns the
/// listener plus the minted token; serving starts once the caller owns the
/// shared report.
async fn bind_early_rendezvous(
    dirs: &ProfileDirs,
    lock: &SessionLock,
) -> Result<(Option<tokio::net::TcpListener>, String, bool), String> {
    // A child may only publish a rendezvous while it owns the session lock:
    // if another process stole or replaced the lock, this child would be a
    // second writer for the same control.json.
    lock.assert_ours(dirs)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("control channel unavailable: {e}"))?;
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let token = control::new_token();
    control::write_control_file(
        dirs,
        &control::ControlInfo {
            port,
            token: token.clone(),
            pid: std::process::id(),
        },
    )
    .map_err(|e| {
        format!(
            "cannot write control file {}: {e}",
            control::control_file(dirs).display()
        )
    })?;
    Ok((Some(listener), token, true))
}

/// Emit a connect failure exactly once (one JSON doc with `--json`, else a
/// stderr diagnostic), tear down the early rendezvous of a detached child,
/// and return the mapped exit code.
fn finish_connect_failure(
    json: bool,
    fail: impl FnOnce() -> qcore_transport_api::FailureReport,
    early_rendezvous: bool,
    dirs: &ProfileDirs,
) -> i32 {
    let r = fail();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": false,
                "layer": r.layer.to_string(),
                "hop_id": qcore_core::diag::masked_value("hop_id", &r.hop_id),
                "kind": r.kind,
                "cause": qcore_core::diag::masked_value("cause", &r.cause),
            })
        );
    }
    if early_rendezvous {
        control::remove_control_file(dirs);
    }
    report::emit_failure(&r)
}

/// Detached parent (T046): spawn the session child, wait for UP on the
/// control channel, then exit. The child owns hops + files from here on.
async fn spawn_detached(o: ConnectOpts) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            exit::diag_exit(
                exit::HOP_FAILURE,
                &format!("cannot re-spawn for --detach: {e}"),
            );
            return exit::HOP_FAILURE;
        }
    };
    let dirs = o.globals_dirs.clone();
    let log_path = dirs.config_dir.join("detached.log");
    let _ = dirs.ensure_dirs();
    // Unbounded-log cap (P3): the append-only detached log grows forever.
    // Before reopening it in append mode, rotate a >10 MiB log to a
    // pid-unique `detached.log.<pid>` (see `rotate_if_oversized`).
    rotate_if_oversized(&log_path, 10 * 1024 * 1024);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);
    let Ok(log_file) = log else {
        exit::diag_exit(
            exit::HOP_FAILURE,
            &format!("cannot open log {}", log_path.display()),
        );
        return exit::HOP_FAILURE;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("connect").arg("--child");
    if let Some(ref c) = o.shortcut_expr {
        cmd.arg("--chain").arg(c);
    } else {
        if let Some(ref c) = o.chain {
            cmd.arg("--chain").arg(c);
        }
        if let Some(ref f) = o.chain_file {
            cmd.arg("--chain-file").arg(f);
        }
        for h in &o.hop {
            cmd.arg("--hop").arg(h);
        }
        if let Some(ref f) = o.file {
            cmd.arg(f);
        }
    }
    cmd.arg("--family")
        .arg(&o.family)
        .arg("--prefer")
        .arg(&o.prefer)
        .arg("--log-level")
        .arg(&o.log_level);
    if let Some(ref b) = o.bind {
        cmd.arg("--bind").arg(b);
    }
    if let Some(ref h) = o.http_proxy {
        cmd.arg("--http-proxy").arg(h);
    }
    if o.expose_lan {
        cmd.arg("--expose-lan");
    }
    if !o.scan {
        cmd.arg("--no-scan");
    }
    if let Some(ref profile) = o.obfuscation {
        cmd.arg("--obfuscation").arg(profile);
    }
    if let Some(ref ip) = o.dns {
        cmd.arg("--dns").arg(ip);
    }
    if let Some(ref ka) = o.keepalive {
        cmd.arg("--keepalive").arg(ka);
    }
    if let Some(ref routing) = o.routing {
        cmd.arg("--routing").arg(routing);
    }
    // Detached child writes the report itself; forward so --detach keeps
    // the same --report-out contract as foreground connect.
    if let Some(r) = o.report_out.as_deref() {
        cmd.arg("--report-out").arg(r);
    }
    // Globals survive the re-spawn so the child uses the same dirs/budget.
    if let Some(d) = o.globals_max_depth {
        cmd.arg("--max-depth").arg(d.to_string());
    }
    cmd.arg("--timeout").arg(o.globals_timeout.to_string());
    if let Some(ref c) = o.globals_config {
        cmd.arg("--config").arg(c);
    }
    if let Some(ref p) = o.globals_profile_dir {
        cmd.arg("--profile-dir").arg(p);
    }
    if o.globals_quiet {
        cmd.arg("--quiet");
    }
    for _ in 0..o.globals_verbose {
        cmd.arg("--verbose");
    }
    if o.json {
        cmd.arg("--json");
    }
    cmd.stdin(std::process::Stdio::null());
    // Panic-free detach: a failed stdout clone is a typed hop-failure
    // (exit 3), never .expect()/panic — e.g. unwritable temp log path.
    let stdout_log = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            exit::diag_exit(
                exit::HOP_FAILURE,
                &format!("cannot clone log {}: {e}", log_path.display()),
            );
            return exit::HOP_FAILURE;
        }
    };
    cmd.stdout(stdout_log).stderr(log_file);
    #[cfg(windows)]
    let spawn_res = {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // CREATE_BREAKAWAY_FROM_JOB: without it a child spawned from a job
        // object (Windows Terminal, some shells/CI runners) is killed when
        // the parent's job closes, so `--detach` would not outlive the
        // invoking shell.
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB);
        match cmd.spawn() {
            // ERROR_ACCESS_DENIED: the job does not permit breakaway (a
            // documented fail mode). Retry without it: a child that outlives
            // the shell until the job ends is still better than no detach.
            Err(e) if e.raw_os_error() == Some(5) => {
                cmd.creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW);
                cmd.spawn()
            }
            other => other,
        }
    };
    #[cfg(not(windows))]
    let spawn_res = cmd.spawn();
    let mut child = match spawn_res {
        Ok(c) => c,
        Err(e) => {
            exit::diag_exit(exit::HOP_FAILURE, &format!("detach spawn failed: {e}"));
            return exit::HOP_FAILURE;
        }
    };
    // Wait for the child's control channel to report UP. The child writes
    // control.json (and serves STATUS with a starting-shape report) before
    // the identity round-trip, so a live child is observable within the
    // first second. Budget: the child's own worst-case startup
    // (preconnect_identity 20 s + engine.start --timeout 30 s + discovery
    // slack) is the floor, and every STATUS answer from a live child
    // extends the deadline — the parent only gives up when the child stops
    // answering while not UP (wedged process), capped so a hung tunnel
    // bring-up cannot pin the parent forever.
    const CHILD_PRECONNECT_BUDGET_SECS: u64 = 20;
    const CHILD_DISCOVERY_SLACK_SECS: u64 = 35;
    const STARTUP_MARGIN_SECS: u64 = 10;
    let base_budget = std::time::Duration::from_secs(
        CHILD_PRECONNECT_BUDGET_SECS
            + o.globals_timeout.max(1)
            + CHILD_DISCOVERY_SLACK_SECS
            + STARTUP_MARGIN_SECS,
    );
    let poll_cap = base_budget + std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let mut last_progress = start;
    let mut final_report: Option<String> = None;
    // Stale-rendezvous guard (P1): the parent may poll while the PREVIOUS
    // session's control.json is still on disk (its port can even be held by
    // an unrelated listener). Only a control.json that CHANGED after the
    // spawn proves the child wrote its rendezvous; byte-identical files are
    // ignored for liveness/UP purposes.
    let control_snapshot = std::fs::read(control::control_file(&dirs)).ok();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                // Interrupted while waiting for UP: attempt exactly one STOP
                // through the child's rendezvous, then make sure no
                // half-started child is left behind and exit non-zero. The
                // detach success line is never printed on this path.
                if let Some(info) = control::read_control_file(&dirs) {
                    let addr = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        info.port,
                    );
                    let _ = control::send_stop(addr, &info.token);
                }
                let _ = child.kill();
                let _ = child.wait();
                clear_reaped_child_lock(&dirs, child.id());
                exit::diag_exit(
                    exit::HOP_FAILURE,
                    "detach interrupted before the session reported UP",
                );
                detach_parent_failure(&o, "detach interrupted before the session reported UP");
                return exit::HOP_FAILURE;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
        }
        let mut saw_live_child = false;
        let control_changed = std::fs::read(control::control_file(&dirs))
            .ok()
            .map(|cur| control_snapshot.as_deref() != Some(cur.as_slice()))
            .unwrap_or(false);
        if control_changed {
            if let Some(info) = control::read_control_file(&dirs) {
                let addr = std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    info.port,
                );
                match control::query_status(addr, &info.token) {
                    Ok(doc) => {
                        saw_live_child = true;
                        last_progress = std::time::Instant::now();
                        // UP = the live report shape (any real hop report, i.e.
                        // not the starting marker). Keep the document for the
                        // parent's own stdout emission.
                        if doc.contains(STARTING_EXIT_MARKER) {
                            // still starting: fall through to the alive checks
                        } else {
                            final_report = Some(doc);
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::ConnectionRefused
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // Rendezvous written but listener not accepting: the
                        // process-alive check below decides.
                    }
                    Err(_) => {}
                }
            }
        }
        if final_report.is_some() {
            break;
        }
        match child.try_wait() {
            Ok(Some(_)) => {
                clear_reaped_child_lock(&dirs, child.id());
                exit::diag_exit(
                    exit::HOP_FAILURE,
                    &format!(
                        "detached child exited before UP (see {})",
                        log_path.display()
                    ),
                );
                detach_parent_failure(&o, "detached child exited before UP");
                return exit::HOP_FAILURE;
            }
            Ok(None) => saw_live_child = true,
            Err(_) => {}
        }
        // A live child that keeps answering keeps the deadline open; a
        // silent stretch beyond the poll cap fails closed (exit 3) instead
        // of waiting forever.
        if start.elapsed() > poll_cap || (!saw_live_child && last_progress.elapsed() > base_budget)
        {
            exit::diag_exit(
                exit::HOP_FAILURE,
                "detached child did not report UP in time",
            );
            let _ = child.kill();
            let _ = child.wait();
            clear_reaped_child_lock(&dirs, child.id());
            detach_parent_failure(&o, "detached child did not report UP in time");
            return exit::HOP_FAILURE;
        }
    }
    // A single UP report only proves the child reached Up once. Re-probe
    // ~1 s later so a child that dies immediately after UP is reported as a
    // failure, not as a detached session the operator cannot use.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let still_live = control::read_control_file(&dirs).is_some_and(|info| {
        let addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            info.port,
        );
        control::query_status(addr, &info.token)
            .map(|status| !status.contains(STARTING_EXIT_MARKER))
            .unwrap_or(false)
    });
    if !still_live {
        // A child that reached UP and then stopped answering is unusable and
        // would hold the session lock: reap it before reporting failure so
        // the next `connect` is not blocked by a session nobody can reach.
        let _ = child.kill();
        let _ = child.wait();
        clear_reaped_child_lock(&dirs, child.id());
        exit::diag_exit(
            exit::HOP_FAILURE,
            &format!(
                "detached child stopped right after UP (see {})",
                log_path.display()
            ),
        );
        detach_parent_failure(&o, "detached child stopped right after UP");
        return exit::HOP_FAILURE;
    }
    eprintln!("qcore: session detached (pid up)");
    // The parent observed UP: forward the child's report so `--json
    // connect --detach` still prints exactly one JSON document on stdout
    // (contract), and text mode gets the same report as foreground.
    let doc = final_report.unwrap_or_default();
    if o.json {
        println!("{doc}");
    } else if let Ok(parsed) = serde_json::from_str::<report::ConnectionReport>(&doc) {
        print!("{}", report::to_text(&parsed));
    } else {
        eprintln!("qcore: session detached (report unavailable)");
    }
    exit::SUCCESS
}

/// Detach-parent failure: with `--json`, stdout must still carry exactly one
/// result document (one-document asymmetry fix, P2). The child owns the
/// report surface in every success path; on parent-side failure there is no
/// child report, so the parent emits the failure shape itself.
fn detach_parent_failure(o: &ConnectOpts, reason: &str) {
    if o.json {
        println!(
            "{}",
            serde_json::json!({
                "ok": false,
                "layer": qcore_transport_api::FailureLayer::Sidecar.to_string(),
                "hop_id": "",
                "kind": "detach",
                "cause": reason,
            })
        );
    }
}

/// The session lock token starts with the owner pid (`<pid>-<nanos>-<n>`).
/// After the parent kills or reaps a child it spawned, clearing that child's
/// lock keeps the next `connect` from waiting out the 10-minute stale
/// window. Ownership is proven by that pid prefix, so a live lock from a
/// different process is never touched.
fn clear_reaped_child_lock(dirs: &ProfileDirs, child_pid: u32) {
    let path = qcore_core::session::session_lock_path(dirs);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return;
    };
    let owner = content
        .lines()
        .next()
        .and_then(|token| token.split('-').next())
        .and_then(|pid| pid.parse::<u32>().ok());
    if owner == Some(child_pid) {
        let _ = std::fs::remove_file(&path);
    }
}

/// Rotate `detached.log` to a pid-unique `detached.log.<pid>` when it
/// exceeds `cap` bytes, so the append-only detach log cannot grow unbounded
/// and two detach parents racing never overwrite each other's copy. Best
/// effort: rotation failure never blocks the detach itself (the append open
/// below still succeeds or fails on its own).
fn rotate_if_oversized(log_path: &std::path::Path, cap: u64) {
    let oversized = std::fs::metadata(log_path)
        .map(|m| m.len() > cap)
        .unwrap_or(false);
    if !oversized {
        return;
    }
    let mut rotated = log_path.as_os_str().to_owned();
    rotated.push(format!(".{}", std::process::id()));
    let _ = std::fs::rename(log_path, std::path::PathBuf::from(rotated));
}

fn run_status(json: bool, dirs: &ProfileDirs) -> i32 {
    let dirs = dirs.clone();
    match SessionStatus::read(&dirs) {
        SessionStatus::NotRunning => {
            if json {
                println!("{}", serde_json::json!({"state": "not_running"}));
            } else {
                eprintln!("qcore: no session (exit 10)");
            }
            exit::NO_SESSION
        }
        SessionStatus::Dead { id } => {
            if json {
                println!("{}", serde_json::json!({"state": "dead", "id": id}));
            } else {
                eprintln!("qcore: session {id} is dead (exit 1)");
            }
            1
        }
        SessionStatus::Unverifiable { session } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"state": "unverifiable", "id": session.id})
                );
            } else {
                eprintln!(
                    "qcore: session {} unverifiable — fail closed (exit 12)",
                    session.id
                );
            }
            exit::UNVERIFIABLE
        }
        SessionStatus::Live { report } => {
            report::emit_report(&report, json);
            if !json {
                // One line when routing rules are configured at the profile
                // default. The report schema is frozen, and an explicit
                // `--routing` path is not persisted; connect's own stderr
                // line (and the detached log) names the actually loaded
                // file.
                let path = dirs
                    .profile_dir
                    .join(qcore_core::config::routing::ROUTING_FILE);
                if path.is_file() {
                    eprintln!(
                        "qcore: routing rules configured at {} (connect --routing overrides)",
                        path.display()
                    );
                }
            }
            exit::SUCCESS
        }
    }
}

fn run_stop(json: bool, dirs: &ProfileDirs) -> i32 {
    let dirs = dirs.clone();
    if let Some(info) = control::read_control_file(&dirs) {
        let addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            info.port,
        );
        match control::send_stop(addr, &info.token) {
            Ok(()) => {
                if json {
                    println!("{}", serde_json::json!({"state": "stopping"}));
                } else {
                    eprintln!("qcore: session stopping");
                }
                return exit::SUCCESS;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // Control process is observably gone (nothing listens):
                // converge the records so a later status reports dead (not
                // stale-up) instead of lingering.
                control::remove_control_file(&dirs);
                mark_stopped(&dirs);
            }
            Err(e) if is_bad_token(&e) => {
                // Explicit `ERR bad token` reply: the listener is NOT our
                // session (stale control.json pointing at an unrelated
                // process that took the port). That is proof-not-ours, not
                // an unverifiable session. The core stop-probe (wave C2)
                // owns the BadToken→Dead record convergence — call it so
                // the records converge through the shared helper; it is
                // idempotent with the local cleanup below (it may report a
                // racing writer's Dead/NoRecord verdict; every conclusive
                // verdict lands in the same clean-stop outcome).
                let _ = SessionStatus::stop_probe(&dirs);
                exit::diag_exit(
                    exit::SUCCESS,
                    "stale control file (listener rejected the token); session treated as stopped",
                );
                control::remove_control_file(&dirs);
                mark_stopped(&dirs);
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"state": "dead", "note": "stale control file; token rejected by listener"})
                    );
                }
                return exit::SUCCESS;
            }
            Err(e) => {
                // A timeout or any other IO error is NOT proof of death:
                // the session may be alive and passing traffic behind a
                // wedged listener (500 ms connect / 2 s read budgets). Fail
                // closed as unverifiable and leave control.json untouched
                // so a retry (or a recovered process) can still answer.
                exit::diag_exit(
                    exit::UNVERIFIABLE,
                    &format!("session unverifiable — fail closed: {e}"),
                );
                return exit::UNVERIFIABLE;
            }
        }
    }
    match SessionStatus::read(&dirs) {
        SessionStatus::NotRunning => {
            if json {
                println!("{}", serde_json::json!({"state": "not_running"}));
            } else {
                eprintln!("qcore: no session (exit 10)");
            }
            exit::NO_SESSION
        }
        SessionStatus::Dead { id } => {
            if json {
                println!("{}", serde_json::json!({"state": "dead", "id": id}));
            } else {
                eprintln!("qcore: session {id} already stopped");
            }
            exit::SUCCESS
        }
        SessionStatus::Unverifiable { session } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"state": "unverifiable", "id": session.id})
                );
            } else {
                eprintln!(
                    "qcore: session {} unverifiable — fail closed (exit 12)",
                    session.id
                );
            }
            exit::UNVERIFIABLE
        }
        SessionStatus::Live { .. } => {
            // Unreachable by construction: every path that reaches
            // SessionStatus::read here has already removed control.json
            // (refused / bad-token convergence above), so `confirm` cannot
            // observe a Live session — it sees NotRunning (no rendezvous)
            // or Dead. Kept fail-closed (exit 12) as the defensive arm.
            if json {
                println!("{}", serde_json::json!({"state": "live"}));
            } else {
                eprintln!("qcore: session live but control refused STOP — fail closed (exit 12)");
            }
            exit::UNVERIFIABLE
        }
    }
}

/// True when the control-channel error is an explicit `ERR bad token` reply.
/// `rejection_error` (core control.rs) surfaces it as PermissionDenied with
/// the fixed text `ERR bad token (listener rejected the token)`; the prefix
/// match is the documented convergence contract (core `confirm`/`stop_probe`
/// use the identical `starts_with("ERR bad token")` test). A hostile
/// listener's own line never reaches this surface (fixed text, no peer
/// bytes), so the prefix proves OUR channel classified a foreign listener;
/// only an explicit reply proves it, a bare PermissionDenied-shaped timeout
/// would not match.
///
/// `ControlInfo.pid` is deliberately NOT consulted for liveness here: a
/// dependency-free Windows check (no `sysinfo`, no `OpenProcess`) would need
/// either a heavy `tasklist` subprocess or undocumented PID-reuse heuristics,
/// and pid reuse makes "pid alive" ≢ "our session alive" anyway. The
/// token-authenticated control channel is the authoritative proof: an
/// explicit `ERR bad token` is conclusive (ours always holds the token), so
/// the convergence below needs no pid. The field stays reserved for future
/// diagnostics-only display.
fn is_bad_token(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied && e.to_string().starts_with("ERR bad token")
}

/// Best-effort convergence: record the session Stopped when its control
/// process is observably gone. The stop contract is already satisfied at
/// that point; a failed convergence leaves a stale-up record that the next
/// `status` re-probes and converges, so it warns instead of failing a proven
/// stop.
fn mark_stopped(dirs: &ProfileDirs) {
    if let Ok(mut session) = Session::load(dirs) {
        session.state = SessionState::Stopped;
        if let Err(e) = session.save(dirs) {
            // Informational note, not the `(exit N)` failure shape: the stop
            // contract is already satisfied and exits 0.
            eprintln!("qcore: note: session record convergence failed (stop succeeded): {e}");
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cli(command: Commands, json: bool) -> Cli {
        Cli {
            json,
            config: Some(std::env::temp_dir().join(format!("qcore-main-{}", std::process::id()))),
            profile_dir: None,
            max_depth: None,
            timeout: None,
            no_color: true,
            quiet: true,
            verbose: 0,
            non_interactive: true,
            yes: false,
            command,
        }
    }

    /// Parse a `connect` argv the way the real binary does (clap), so the
    /// flag defaults under test are the shipped ones, not hand-built structs.
    /// Returns the clap error kind on rejection (`Cli` has no `Debug`, so
    /// the error is inspected without `expect_err`).
    fn parse_connect_kind(args: &[&str]) -> Result<(), clap::error::ErrorKind> {
        let mut argv = vec!["qcore", "connect"];
        argv.extend_from_slice(args);
        match Cli::try_parse_from(&argv) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.kind()),
        }
    }

    fn parse_connect(args: &[&str]) -> Cli {
        let mut argv = vec!["qcore", "connect"];
        argv.extend_from_slice(args);
        Cli::try_parse_from(&argv).expect("connect argv parses")
    }

    fn connect_scan(cli: &Cli) -> bool {
        match &cli.command {
            Commands::Connect { no_scan, .. } => !*no_scan,
            _ => panic!("expected connect subcommand"),
        }
    }

    #[tokio::test]
    async fn connect_bad_family_is_usage() {
        let cli = test_cli(
            Commands::Connect {
                chain: None,
                chain_file: None,
                hop: vec![],
                file: None,
                family: "bogus".to_string(),
                prefer: "ipv4".to_string(),
                report_out: None,
                log_level: "info".to_string(),
                detach: false,
                bind: None,
                expose_lan: false,
                http_proxy: None,
                child: false,
                no_scan: true,
                obfuscation: None,
                dns: None,
                keepalive: None,
                routing: None,
            },
            false,
        );
        assert_eq!(async_main(cli).await, exit::USAGE);
    }

    #[test]
    fn clap_usage_error_collapses_to_one_line() {
        // contracts/cli.md §2: clap-level usage errors are exit 6 and the
        // diagnostic is one line, never clap's multi-line block. The
        // `diag_exit` prefix already frames the line, so clap's own
        // `error: ` prefix and its usage/`--help` trailer are stripped: the
        // remaining text is the core message, not a run-on sentence.
        let err = match Cli::try_parse_from(["qcore", "--nope"]) {
            Ok(_) => panic!("unknown flag must not parse"),
            Err(e) => e,
        };
        let msg = collapsed_clap_message(&err);
        assert!(!msg.contains('\n'), "one line only: {msg:?}");
        assert!(
            msg.starts_with("unexpected argument"),
            "clap's `error: ` framing is stripped: {msg:?}"
        );
        assert!(
            msg.contains("--nope"),
            "names the offending argument: {msg:?}"
        );
        assert!(
            !msg.contains("Usage:") && !msg.contains("For more information"),
            "clap's usage block and help hint are dropped: {msg:?}"
        );
        assert_eq!(clap_exit(&err), exit::USAGE);
    }

    #[test]
    fn bind_policy_loopback_is_allowed() {
        let a: std::net::SocketAddr = "127.0.0.1:1080".parse().unwrap();
        assert!(bind_policy(a, false).is_ok(), "loopback needs no opt-in");
        assert!(bind_policy(a, true).is_ok());
    }

    #[test]
    fn bind_policy_non_loopback_requires_expose_lan() {
        // The unauthenticated SOCKS listener must refuse LAN/wildcard binds
        // unless --expose-lan opted in (open-proxy fail-safe default).
        for addr in ["0.0.0.0:1080", "192.168.1.10:1080", "10.0.0.2:1080"] {
            let a: std::net::SocketAddr = addr.parse().unwrap();
            assert_eq!(
                bind_policy(a, false).err(),
                Some("refusing non-loopback --bind without --expose-lan"),
                "{addr} refused without opt-in"
            );
            assert!(bind_policy(a, true).is_ok(), "{addr} allowed with opt-in");
        }
        // IPv6 loopback and unspecified: loopback allowed, unspecified
        // (:: binds every interface) requires the opt-in like 0.0.0.0.
        let v6_loopback: std::net::SocketAddr = "[::1]:1080".parse().unwrap();
        assert!(bind_policy(v6_loopback, false).is_ok());
        let v6_any: std::net::SocketAddr = "[::]:1080".parse().unwrap();
        assert!(bind_policy(v6_any, false).is_err(), ":: is not loopback");
        assert!(bind_policy(v6_any, true).is_ok());
    }

    #[test]
    fn expose_lan_flag_parses_through_clap() {
        let cli = parse_connect(&["--chain", "mock", "--bind", "0.0.0.0:1080", "--expose-lan"]);
        match &cli.command {
            Commands::Connect {
                bind, expose_lan, ..
            } => {
                assert_eq!(bind.as_deref(), Some("0.0.0.0:1080"));
                assert!(expose_lan, "--expose-lan parses");
            }
            _ => panic!("expected connect subcommand"),
        }
    }

    #[test]
    fn http_proxy_flag_parses_through_clap() {
        // Default off: a plain connect carries no HTTP listener.
        let cli = parse_connect(&["--chain", "mock"]);
        match &cli.command {
            Commands::Connect { http_proxy, .. } => {
                assert_eq!(http_proxy.as_deref(), None, "--http-proxy default off");
            }
            _ => panic!("expected connect subcommand"),
        }
        // Explicit value parses as-is (127.0.0.1:0 = ephemeral port).
        let cli = parse_connect(&["--chain", "mock", "--http-proxy", "127.0.0.1:0"]);
        match &cli.command {
            Commands::Connect { http_proxy, .. } => {
                assert_eq!(http_proxy.as_deref(), Some("127.0.0.1:0"));
            }
            _ => panic!("expected connect subcommand"),
        }
    }

    #[test]
    fn http_proxy_policy_matches_bind_policy() {
        // Non-loopback --http-proxy is refused without --expose-lan, allowed
        // with it — the same fail-safe open-proxy rule as --bind.
        let lan: std::net::SocketAddr = "192.168.1.10:8080".parse().unwrap();
        assert_eq!(
            bind_policy(lan, false).err(),
            Some("refusing non-loopback --bind without --expose-lan"),
            "non-loopback http-proxy refused without opt-in (shared bind_policy)"
        );
        assert!(bind_policy(lan, true).is_ok(), "opt-in allows the LAN bind");
        // Loopback never needs the opt-in.
        let lo: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(bind_policy(lo, false).is_ok());
    }

    #[test]
    fn rotate_if_oversized_moves_oversized_log() {
        let dir = std::env::temp_dir().join(format!("qcore-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("detached.log");
        std::fs::write(&log, vec![b'x'; 4096]).unwrap();
        rotate_if_oversized(&log, 1024);
        assert!(!log.exists(), "oversized log renamed away");
        let rotated = dir.join(format!("detached.log.{}", std::process::id()));
        assert_eq!(std::fs::metadata(&rotated).unwrap().len(), 4096);
        // Under-cap logs stay in place.
        std::fs::write(&log, b"small").unwrap();
        rotate_if_oversized(&log, 1024);
        assert!(log.exists(), "under-cap log untouched");
        assert_eq!(std::fs::metadata(&log).unwrap().len(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ls_with_json_is_usage() {
        let cli = test_cli(Commands::Ls, true);
        assert_eq!(async_main(cli).await, exit::USAGE);
    }

    #[test]
    fn connect_scan_defaults_on_through_clap() {
        let cli = parse_connect(&["--chain", "mock"]);
        assert!(connect_scan(&cli), "discovery on by default");
    }

    #[test]
    fn connect_no_scan_disables_discovery_through_clap() {
        let cli = parse_connect(&["--chain", "mock", "--no-scan"]);
        assert!(!connect_scan(&cli), "--no-scan turns discovery off");
    }

    #[test]
    fn connect_scan_flag_is_no_longer_accepted() {
        // The old `--scan` flag was unusable via argv (declared
        // default_value_t = true + SetTrue) and made every `--no-scan`
        // invocation exit 6 through the conflict guard. It is gone: clap
        // must reject it with a usage error.
        assert_eq!(
            parse_connect_kind(&["--chain", "mock", "--scan"]),
            Err(clap::error::ErrorKind::UnknownArgument),
            "--scan is no longer a flag"
        );
        assert_eq!(
            parse_connect_kind(&["--chain", "mock", "--scan", "--no-scan"]),
            Err(clap::error::ErrorKind::UnknownArgument),
            "--scan stays rejected even with --no-scan"
        );
    }
}
