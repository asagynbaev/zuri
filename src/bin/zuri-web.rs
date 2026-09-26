//! Demo web app. The employee page works with the employee's key, the way a
//! wallet would. The verifier page only uses the proof file and chain data.

use {
    anyhow::{Context, ensure},
    axum::{
        Json, Router,
        extract::State,
        http::{StatusCode, header},
        response::{Html, IntoResponse, Response},
        routing::{get, post},
    },
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    solana_address::Address,
    solana_keypair::Keypair,
    solana_rpc_client::nonblocking::rpc_client::RpcClient,
    std::{collections::BTreeMap, path::PathBuf, str::FromStr, sync::Arc, time::SystemTime},
    zuri::{chain, keys, parse_amount, proof, store::Payroll},
};

struct App {
    rpc: RpcClient,
    employee: Keypair,
    employer: Address,
    mint: Address,
}

type Shared = State<Arc<App>>;

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "error": format!("{:#}", self.0) });
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let payroll = Payroll::load()?;
    ensure!(!payroll.mint.is_empty(), "run `zuri setup` first");
    let app = Arc::new(App {
        rpc: chain::rpc(),
        employee: keys::keypair("employee")?,
        employer: Address::from_str(&payroll.employer)?,
        mint: Address::from_str(&payroll.mint)?,
    });

    let css = (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("../../web/app.css"),
    );
    let js = (
        [(header::CONTENT_TYPE, "text/javascript")],
        include_str!("../../web/app.js"),
    );
    let router = Router::new()
        .route("/", get(Html(include_str!("../../web/employee.html"))))
        .route("/v/{id}", get(Html(include_str!("../../web/verify.html"))))
        .route("/app.css", get(css))
        .route("/app.js", get(js))
        .route("/api/income", get(income))
        .route("/api/proofs", post(create_proof))
        .route("/api/verify", post(verify))
        .with_state(app);

    let port: u16 = std::env::var("ZURI_PORT").map_or(Ok(8787), |p| p.parse())?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    println!("listening on http://localhost:{port}");
    axum::serve(listener, router).await?;
    Ok(())
}

fn transfer_refs() -> anyhow::Result<Vec<zuri::onchain::TransferRef>> {
    Payroll::load()?.transfer_refs()
}

#[derive(Serialize)]
struct Income {
    employee: String,
    employer: String,
    months: Vec<Month>,
}

#[derive(Serialize)]
struct Month {
    period: String,
    total: u64,
    payments: Vec<PaymentView>,
}

#[derive(Serialize)]
struct PaymentView {
    signature: String,
    amount: u64,
    paid_at: Option<i64>,
}

async fn income(State(app): Shared) -> ApiResult<Income> {
    let payments = proof::payments(&app.rpc, &app.employee, &app.mint, &transfer_refs()?).await?;
    let mut months: BTreeMap<String, Month> = BTreeMap::new();
    for p in payments {
        let period = p.transfer.period()?;
        let month = months.entry(period.clone()).or_insert(Month {
            period,
            total: 0,
            payments: vec![],
        });
        month.total += p.amount;
        month.payments.push(PaymentView {
            signature: p.transfer.signature.to_string(),
            amount: p.amount,
            paid_at: p.transfer.block_time,
        });
    }
    Ok(Json(Income {
        employee: solana_signer::Signer::pubkey(&app.employee).to_string(),
        employer: app.employer.to_string(),
        months: months.into_values().collect(),
    }))
}

fn proof_path(id: &str) -> anyhow::Result<PathBuf> {
    ensure!(
        !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()),
        "bad proof id"
    );
    Ok(PathBuf::from(keys::DIR)
        .join("proofs")
        .join(format!("{id}.json")))
}

#[derive(Deserialize)]
struct NewProof {
    min: String,
    months: usize,
}

#[derive(Serialize)]
struct Created {
    id: String,
}

/// Payments of the last `n` months that have any salary.
fn last_months(payments: Vec<proof::Payment>, n: usize) -> anyhow::Result<Vec<proof::Payment>> {
    let mut periods = payments
        .iter()
        .map(|p| p.transfer.period())
        .collect::<anyhow::Result<Vec<_>>>()?;
    periods.sort();
    periods.dedup();
    ensure!(
        (1..=periods.len()).contains(&n),
        "there is salary for {} months",
        periods.len()
    );
    let chosen = &periods[periods.len() - n..];
    let mut selected = vec![];
    for p in payments {
        if chosen.contains(&p.transfer.period()?) {
            selected.push(p);
        }
    }
    Ok(selected)
}

async fn create_proof(State(app): Shared, Json(req): Json<NewProof>) -> ApiResult<Created> {
    let min = parse_amount(&req.min)?;
    let payments = proof::payments(&app.rpc, &app.employee, &app.mint, &transfer_refs()?).await?;
    let selected = last_months(payments, req.months)?;
    let (proof, _) = proof::prove(&app.employee, &app.mint, &selected, min, true)?;
    let json = serde_json::to_string_pretty(&proof)?;
    let id: String = Sha256::digest(&json)[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let path = proof_path(&id)?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, json)?;
    Ok(Json(Created { id }))
}

#[derive(Deserialize)]
struct Check {
    id: String,
    employer: String,
    min: String,
    months: Option<usize>,
}

#[derive(Serialize)]
struct PeriodView {
    label: String,
    transfers: Vec<String>,
}

#[derive(Serialize)]
struct Checked {
    ok: bool,
    error: Option<String>,
    employee: String,
    min: u64,
    periods: Vec<PeriodView>,
    transfers: usize,
    first_time: Option<i64>,
    last_time: Option<i64>,
    tx_set_hash: Option<String>,
    checked_at: u64,
}

async fn verify(State(app): Shared, Json(req): Json<Check>) -> ApiResult<Checked> {
    let file = std::fs::read_to_string(proof_path(&req.id)?).context("no such proof")?;
    let income: proof::IncomeProof = serde_json::from_str(&file)?;
    let employer = Address::from_str(req.employer.trim()).context("bad employer address")?;
    let min = parse_amount(req.min.trim())?;

    let result = async {
        let verdict = proof::verify(&app.rpc, &income, &employer, min).await?;
        if let Some(n) = req.months {
            proof::check_consecutive(&verdict.periods, n)?;
        }
        anyhow::Ok(verdict)
    }
    .await;

    let checked_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let periods = income
        .periods
        .iter()
        .map(|p| PeriodView {
            label: p.label.clone(),
            transfers: p.transfers.iter().map(|t| t.transfer.clone()).collect(),
        })
        .collect();
    let transfers = income.periods.iter().map(|p| p.transfers.len()).sum();
    Ok(Json(match result {
        Ok(v) => Checked {
            ok: true,
            error: None,
            employee: income.employee,
            min,
            periods,
            transfers: v.transfers,
            first_time: v.first_time,
            last_time: v.last_time,
            tx_set_hash: Some(v.tx_set_hash),
            checked_at,
        },
        Err(e) => Checked {
            ok: false,
            error: Some(format!("{e:#}")),
            employee: income.employee,
            min,
            periods,
            transfers,
            first_time: None,
            last_time: None,
            tx_set_hash: None,
            checked_at,
        },
    }))
}
