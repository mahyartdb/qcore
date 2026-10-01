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
use qcore_core::session::{reconnect, Session, SessionState, SessionStatus};

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
}

fn check_globals(cli: &Cli) -> Result<GlobalOpts, i32> {
    if let Some(d) = cli.max_depth {
        if !(1..=5).contains(&d) {
            eprintln!("qcore: --max-depth {d} outside 1..=5 (hard limit 5)");
            return Err(exit::USAGE);
        }
    }
    let timeout_secs = cli.timeout.unwrap_or(30);
    if timeout_secs < 1 {
        eprintln!("qcore: --timeout must be at least 1 second (exit 6)");
        return Err(exit::USAGE);
    }
    Ok(GlobalOpts {
        max_depth: cli.max_depth,
        timeout_secs,
        quiet: cli.quiet,
    })
}

fn cli_dirs(cli: &Cli) -> ProfileDirs {
    ProfileDirs::resolve(cli.config.clone(), cli.profile_dir.clone())
}

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
        /// Enable endpoint discovery on connect (default on; scans once when
        /// the chain needs an endpoint and none is cached).
        #[arg(long, default_value_t = true, action = clap::ArgAction::SetTrue)]
        scan: bool,
        /// Disable endpoint discovery on connect.
        #[arg(long)]
        no_scan: bool,
        /// Internal: detached child mode (spawned by --detach, not for users).
        #[arg(long, hide = true)]
        child: bool,
        /// Obfuscation profile chain-default (hops without explicit key inherit).
        #[arg(long = "obfuscation", short = 'O')]
        obfuscation: Option<String>,
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
    // Force linkage of every enabled transport so inventory registration
    // reaches the engine registry (static archives only link used objects).
    let _ = qcore_transports::linked_kinds();
    let cli = Cli::parse();
    let code = run(cli);
    std::process::exit(code);
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
                    eprintln!("qcore: {msg}");
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
            run_shortcut(args, cli.json, dirs, cli.config, cli.profile_dir).await
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
            child,
            scan,
            no_scan,
            obfuscation,
        } => {
            if scan && no_scan {
                eprintln!("qcore: --scan and --no-scan conflict (exit 6)");
                return exit::USAGE;
            }
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
                child,
                scan: scan && !no_scan,
                obfuscation,
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
        } => cmd::scan::run(&transport, &profile, &family, &output, cli.json, &dirs).await,
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
    child: bool,
    /// Endpoint discovery on connect (scan once when needed).
    scan: bool,
    /// Obfuscation profile chain-default.
    obfuscation: Option<String>,
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
) -> i32 {
    let engine = cmd::preflight::default_engine(dirs.clone());
    let presets = match qcore_core::chain::preset::resolve_presets(&dirs) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("qcore: invalid chain (exit 2)\n  {e}");
            return exit::INVALID;
        }
    };
    let name = args.join(" ");
    match cmd::shortcuts::resolve(
        &engine,
        &presets,
        3,
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
                child: false,
                scan: false,
                obfuscation: None,
                globals_max_depth: None,
                globals_timeout: 30,
                globals_quiet: false,
                globals_verbose: 0,
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
            eprintln!("qcore: invalid chain (exit 2)\n  {e}");
            exit::INVALID
        }
    }
}

fn check_level(level: &str) -> Result<u8, i32> {
    match level {
        "error" => Ok(0),
        "warn" => Ok(1),
        "info" => Ok(2),
        "debug" => Ok(3),
        "trace" => Ok(4),
        _ => {
            eprintln!(
                "qcore: invalid --log-level `{level}` (expected error|warn|info|debug|trace)"
            );
            Err(exit::USAGE)
        }
    }
}

async fn run_connect(o: ConnectOpts) -> i32 {
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
        Err(code) => return code,
    };
    let dirs = o.globals_dirs.clone();
    // Fail fast on family/prefer before touching the network (exit 6:
    // unknown families are usage errors, matching `scan --family`).
    if let Err(e) = qcore_core::session::net::FamilyPolicy::parse(&o.family, &o.prefer) {
        eprintln!("qcore: {e} (exit 6)");
        return exit::USAGE;
    }
    let bind_addr: Option<std::net::SocketAddr> = match o.bind {
        Some(ref b) => match b.parse() {
            Ok(a) => Some(a),
            Err(_) => {
                eprintln!("qcore: invalid --bind `{b}` (expected host:port)");
                return exit::USAGE;
            }
        },
        None => None,
    };

    // Detached parent: re-spawn self as the session process, wait for UP.
    if o.detach && !o.child {
        return spawn_detached(o);
    }

    // Cold start (T048): identity first, then chain inputs (zero-config
    // default when nothing was given).
    if let Err(e) = reconnect::ensure_identity(&dirs) {
        eprintln!("qcore: identity unavailable: {e}");
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
                        if code == exit::INVALID {
                            eprintln!("qcore: invalid chain (exit 2)\n  {msg}");
                        } else {
                            eprintln!("qcore: {msg}");
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
        ..Default::default()
    });

    // Provider identities (002 FR-003/004/005): reuse healthy stored
    // identities, auto-register when none is stored, refresh-or-reregister
    // once on refusal, rotate in-window MASQUE credentials. Fail-closed
    // (exit 2) when the provider is unreachable or refuses.
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
        Err(report) => {
            if o.json {
                println!("{}", report.to_json());
            }
            eprintln!("qcore: identity unavailable: {}", report.cause);
            return report.exit_code();
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
    if o.scan && qcore_core::session::reconnect::last_known_good(&dirs).is_none() {
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
                eprintln!("qcore: --bind {addr} unavailable: {e}");
                return exit::HOP_FAILURE;
            }
        },
        None => None,
    };

    let handle = match engine.start(specs).await {
        Ok(h) => h,
        Err(r) => {
            if o.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "layer": r.layer.to_string(),
                        "hop_id": r.hop_id,
                        "kind": r.kind,
                        "cause": qcore_core::diag::masked_value("cause", &r.cause),
                    })
                );
            }
            return report::emit_failure(&r);
        }
    };
    let mut report = ConnectionReport::new(handle.hop_reports(), handle.exit_hop_id.clone());
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

    // Rendezvous for status/stop: control listener, then durable records.
    let control_listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            let _ = handle.stop_all().await;
            eprintln!("qcore: control channel unavailable: {e}");
            return exit::HOP_FAILURE;
        }
    };
    let control_port = control_listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let token = control::new_token();
    let mut session = Session {
        id: handle.id.clone(),
        chain: handle.chain.clone(),
        family_policy: qcore_core::session::net::FamilyPolicy::parse(&o.family, &o.prefer)
            .expect("validated above"),
        state: SessionState::Validating,
        started_at: now_ms(),
        failure: None,
    };
    let _ = session.transition(SessionState::Starting);
    let _ = session.transition(SessionState::Up);
    if session.save(&dirs).is_err() {
        let _ = handle.stop_all().await;
        eprintln!("qcore: cannot write session state");
        return exit::HOP_FAILURE;
    }
    control::write_control_file(
        &dirs,
        &control::ControlInfo {
            port: control_port,
            token: token.clone(),
            pid: std::process::id(),
        },
    )
    .map_err(|e| {
        let _ = session.save(&dirs);
        eprintln!("qcore: cannot write control file: {e}");
    })
    .ok();
    if let Some(path) = o.report_out.as_deref() {
        if std::fs::write(path, report::to_json(&report)).is_err() {
            eprintln!("qcore: cannot write --report-out `{path}`");
        }
    }
    report::emit_report(&report, o.json);

    if let Some(listener) = bind_listener {
        let bound = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        eprintln!(
            "qcore: proxy listening on {bound} (exit {})",
            handle.exit_hop_id
        );
        tokio::spawn(
            qcore_core::session::proxy::serve_socks_via_dialer_with_policy(
                listener,
                handle.dialer(),
                // The session policy (not dual-default): `--family ipv4` refuses
                // IPv6 CONNECT with 0x08 at the SOCKS layer instead of dialing.
                session.family_policy.clone(),
            ),
        );
    }

    // Serve control until STOP or Ctrl-C, then tear down closed.
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(control::serve_control(
        control_listener,
        token,
        report,
        stop_tx,
    ));
    tokio::select! {
        _ = stop_rx => eprintln!("qcore: stop requested"),
        _ = tokio::signal::ctrl_c() => eprintln!("qcore: interrupted"),
    }
    let _ = handle.stop_all().await;
    session.state = SessionState::Stopped;
    let _ = session.save(&dirs);
    control::remove_control_file(&dirs);
    exit::SUCCESS
}

/// Detached parent (T046): spawn the session child, wait for UP on the
/// control channel, then exit. The child owns hops + files from here on.
fn spawn_detached(o: ConnectOpts) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("qcore: cannot re-spawn for --detach: {e}");
            return exit::HOP_FAILURE;
        }
    };
    let dirs = o.globals_dirs.clone();
    let log_path = dirs.config_dir.join("detached.log");
    let _ = dirs.ensure_dirs();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path);
    let Ok(log_file) = log else {
        eprintln!("qcore: cannot open log {}", log_path.display());
        return exit::HOP_FAILURE;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("connect").arg("--child");
    if let Some(c) = o.shortcut_expr {
        cmd.arg("--chain").arg(c);
    } else {
        if let Some(c) = o.chain {
            cmd.arg("--chain").arg(c);
        }
        if let Some(f) = o.chain_file {
            cmd.arg("--chain-file").arg(f);
        }
        for h in o.hop {
            cmd.arg("--hop").arg(h);
        }
        if let Some(f) = o.file {
            cmd.arg(f);
        }
    }
    cmd.arg("--family")
        .arg(&o.family)
        .arg("--prefer")
        .arg(&o.prefer)
        .arg("--log-level")
        .arg(&o.log_level);
    if let Some(b) = o.bind {
        cmd.arg("--bind").arg(b);
    }
    if !o.scan {
        cmd.arg("--no-scan");
    }
    if let Some(profile) = o.obfuscation {
        cmd.arg("--obfuscation").arg(profile);
    }
    // Globals survive the re-spawn so the child uses the same dirs/budget.
    if let Some(d) = o.globals_max_depth {
        cmd.arg("--max-depth").arg(d.to_string());
    }
    cmd.arg("--timeout").arg(o.globals_timeout.to_string());
    if let Some(c) = o.globals_config {
        cmd.arg("--config").arg(c);
    }
    if let Some(p) = o.globals_profile_dir {
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
    cmd.stdin(std::process::Stdio::null())
        .stdout(log_file.try_clone().unwrap_or_else(|_| {
            std::fs::File::create(std::env::temp_dir().join("qcore-null.log"))
                .expect("temp-dir log fallback is writable when detaching")
        }))
        .stderr(log_file);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS | CREATE_NO_WINDOW: no console, outlives parent.
        cmd.creation_flags(0x00000008 | 0x08000000);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("qcore: detach spawn failed: {e}");
            return exit::HOP_FAILURE;
        }
    };
    // Wait for the child's control channel to report UP (10 s budget).
    for _ in 0..100 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(info) = control::read_control_file(&dirs) {
            let addr = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                info.port,
            );
            if control::query_status(addr, &info.token).is_ok() {
                eprintln!("qcore: session detached (pid {})", info.pid);
                return exit::SUCCESS;
            }
        }
        if child.try_wait().ok().flatten().is_some() {
            eprintln!(
                "qcore: detached child exited before UP (see {})",
                log_path.display()
            );
            return exit::HOP_FAILURE;
        }
    }
    eprintln!("qcore: detached child did not report UP in time");
    let _ = child.kill();
    exit::HOP_FAILURE
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
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Control process is gone: converge the records so a later
                // status reports dead (not stale-up) instead of lingering.
                control::remove_control_file(&dirs);
                mark_stopped(&dirs);
            }
            Err(e) => {
                eprintln!("qcore: session unverifiable — fail closed (exit 12): {e}");
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
            if json {
                println!("{}", serde_json::json!({"state": "live"}));
            } else {
                eprintln!("qcore: session live but control refused STOP — fail closed (exit 12)");
            }
            exit::UNVERIFIABLE
        }
    }
}

/// Best-effort convergence: record the session Stopped when its control
/// process is observably gone.
fn mark_stopped(dirs: &ProfileDirs) {
    if let Ok(mut session) = Session::load(dirs) {
        session.state = SessionState::Stopped;
        let _ = session.save(dirs);
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
                child: false,
                scan: false,
                no_scan: true,
                obfuscation: None,
            },
            false,
        );
        assert_eq!(async_main(cli).await, exit::USAGE);
    }

    #[tokio::test]
    async fn ls_with_json_is_usage() {
        let cli = test_cli(Commands::Ls, true);
        assert_eq!(async_main(cli).await, exit::USAGE);
    }
}
