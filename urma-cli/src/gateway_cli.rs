use crate::{
    config::{self, GatewayChoice},
    gateway_host::{LinkScheme, Portal, Suffix},
    gateway_http::{Request, accept_loop},
    gateway_site::respond,
    gateway_state::Gateway,
    progress,
};
use bitcoin::Txid;
use clap::{Args, Subcommand};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::{SocketAddr, TcpListener},
    path::PathBuf,
    sync::mpsc,
};
use urma_runtime::error::{Error, bail, ensure};

#[derive(Subcommand)]
pub(crate) enum GatewayCommand {
    #[command(
        about = "Serve the bound names of one registry per network to ordinary browsers over HTTP"
    )]
    Serve(ServeArgs),
}

#[derive(Args)]
pub(crate) struct ServeArgs {
    #[arg(long, help = "Portal domain; name hosts are <name>.<suffix>.<domain>")]
    domain: String,
    #[arg(
        long = "registry",
        required = true,
        help = "suffix=GENESIS_TXID of the one registry served on that network (ltc, tltc, tbtc); repeat per network"
    )]
    registries: Vec<String>,
    #[arg(long, help = "Listen address; defaults to 127.0.0.1:8080")]
    bind: Option<SocketAddr>,
    #[arg(
        long,
        value_enum,
        help = "Scheme of rewritten links and portal URLs; defaults to https (http for local testing)"
    )]
    scheme: Option<LinkScheme>,
    #[arg(
        long,
        help = "Port written into rewritten links when browsers reach the portal on a non-default port"
    )]
    public_port: Option<u16>,
    #[arg(long, help = "Verified store; defaults to the browser's store")]
    store: Option<PathBuf>,
    #[arg(
        long,
        help = "Names index directory; defaults to the local names directory"
    )]
    names_dir: Option<PathBuf>,
    #[arg(long, help = "Seconds between registry rescans; defaults to 30")]
    rescan_seconds: Option<u64>,
    #[arg(
        long,
        help = "Largest publication payload fetched and verified, in bytes"
    )]
    max_bytes: Option<usize>,
    #[arg(long, help = "HTTP worker threads; defaults to 8")]
    workers: Option<usize>,
}

pub(crate) fn run(command: GatewayCommand) -> Result<Value, Error> {
    match command {
        GatewayCommand::Serve(args) => serve(args),
    }
}

fn parse_registries(rules: &[String]) -> Result<BTreeMap<Suffix, Txid>, Error> {
    let mut registries = BTreeMap::new();
    for rule in rules {
        let Some((label, genesis)) = rule.split_once('=') else {
            bail!("--registry expects suffix=GENESIS_TXID, got {rule:?}");
        };
        let suffix = Suffix::parse(label).map_err(|cause| Error::Invalid(cause.to_string()))?;
        suffix.chain()?;
        let genesis: Txid = genesis.parse()?;
        ensure!(
            !registries.contains_key(&suffix),
            "--registry names the .{} network twice; a portal serves one registry per network",
            suffix.label()
        );
        registries.insert(suffix, genesis);
    }
    Ok(registries)
}

fn serve(args: ServeArgs) -> Result<Value, Error> {
    let settings = config::gateway(GatewayChoice {
        bind: args.bind,
        scheme: args.scheme,
        public_port: args.public_port,
        store: args.store,
        names_dir: args.names_dir,
        rescan_seconds: args.rescan_seconds,
        max_bytes: args.max_bytes,
        workers: args.workers,
    })?;
    let portal = Portal::new(
        &args.domain,
        settings.scheme,
        settings.public_port,
        parse_registries(&args.registries)?,
    )?;
    let (jobs, queue) = mpsc::sync_channel(settings.fetch_queue);
    let gateway = Gateway::open(portal, settings, jobs)?;
    let listener = TcpListener::bind(gateway.settings.bind)?;
    progress(format!(
        "URMA portal {} listening on http://{} (links {})",
        gateway.portal.domain(),
        listener.local_addr()?,
        gateway.portal.apex_origin()
    ));
    let shared = &gateway;
    std::thread::scope(|scope| {
        scope.spawn(|| shared.rescan_loop());
        scope.spawn(move || shared.fetch_loop(queue));
        for _worker in 0..shared.settings.workers {
            scope.spawn(|| {
                accept_loop(&listener, &shared.settings.http, &|request: &Request| {
                    respond(shared, request)
                })
            });
        }
    });
    Ok(Value::Null)
}
