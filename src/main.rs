use std::time::Duration;

use clap::{Parser, ValueEnum};
use tlsaudit::audit::{audit, Options};
use tlsaudit::parse_target;
use tlsaudit::report::{FailOn, Severity};

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum FailOnArg {
    Warn,
    Critical,
    Never,
}

impl From<FailOnArg> for FailOn {
    fn from(v: FailOnArg) -> Self {
        match v {
            FailOnArg::Warn => FailOn::Warn,
            FailOnArg::Critical => FailOn::Critical,
            FailOnArg::Never => FailOn::Never,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "tlsaudit",
    about = "Audit a live endpoint's TLS configuration — protocol versions, weak ciphers, chain and hostname hygiene"
)]
struct Cli {
    /// Endpoints to audit, e.g. `example.com` or `example.com:8443`.
    #[arg(required = true)]
    targets: Vec<String>,

    /// Per-connection connect/read timeout, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Warn when the certificate expires within this many days.
    #[arg(long, default_value_t = 30)]
    warn_days: i64,

    /// Skip the weak-cipher probes (six extra connections per target, and
    /// some WAFs treat a NULL-cipher-only ClientHello as an attack).
    #[arg(long)]
    no_cipher_probes: bool,

    /// Which severity makes the process exit non-zero.
    #[arg(long, value_enum, default_value_t = FailOnArg::Warn)]
    fail_on: FailOnArg,
}

fn main() {
    let cli = Cli::parse();
    let opts = Options {
        timeout: Duration::from_secs(cli.timeout.max(1)),
        skip_ciphers: cli.no_cipher_probes,
        warn_days: cli.warn_days,
    };
    let fail_on: FailOn = cli.fail_on.into();

    let mut worst = Severity::Ok;
    for (i, target) in cli.targets.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let (host, port) = parse_target(target);
        let report = audit(&host, port, &opts);
        print!("{}", report.render());
        worst = worst.max(report.worst());
    }

    // Reuse the report's own exit-code rule rather than re-deriving it here,
    // so the CLI contract and the unit tests cannot drift apart.
    let mut combined = tlsaudit::report::Report::new("");
    combined.section(
        "combined",
        vec![tlsaudit::report::Finding::new(worst, "worst", "")],
    );
    std::process::exit(combined.exit_code(fail_on));
}
