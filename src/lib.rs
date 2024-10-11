use http::{uri::Authority, Uri};
use itertools::Itertools;
use jsonrpsee_core::params::ObjectParams;
use jsonrpsee_core::{self, client::ClientT};
use jsonrpsee_http_client::{HeaderMap, HttpClient, HttpClientBuilder};
use serde_aux::prelude::{
    deserialize_default_from_null, deserialize_number_from_string,
    deserialize_option_number_from_string,
};
use serde_with::{serde_as, DisplayFromStr};
use stellar_xdr::curr::{
    self as xdr, AccountEntry, AccountId, ContractDataEntry, ContractEventType, DiagnosticEvent,
    Error as XdrError, Hash, LedgerEntryData, LedgerFootprint, LedgerKey, LedgerKeyAccount, Limits,
    ReadXdr, ScContractInstance, ScVal, SorobanAuthorizationEntry, SorobanResources,
    SorobanTransactionData, TransactionEnvelope, TransactionMeta, TransactionMetaV3,
    TransactionResult, VecM, WriteXdr,
};

use std::ops::Deref;
use std::{
    f64::consts::E,
    fmt::Display,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use termcolor::{Color, ColorChoice, StandardStream, WriteColor};
use termcolor_output::colored;
use tokio::time::sleep;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");
const MAX_DEPTH: u32 = 1000;

pub type LogEvents = fn(
    footprint: &LedgerFootprint,
    auth: &[VecM<SorobanAuthorizationEntry>],
    events: &[DiagnosticEvent],
) -> ();

pub type LogResources = fn(resources: &SorobanResources) -> ();

#[derive(thiserror::Error, Debug)]
#[allow(deprecated)] // Can be removed once Error enum doesn't have any code marked deprecated inside
pub enum Error {
    #[error(transparent)]
    InvalidAddress(#[from] stellar_strkey::DecodeError),
    #[error("invalid response from server")]
    InvalidResponse,
    #[error("provided network passphrase {expected:?} does not match the server: {server:?}")]
    InvalidNetworkPassphrase { expected: String, server: String },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] XdrError),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrl(http::uri::InvalidUri),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrlFromUriParts(http::uri::InvalidUriParts),
    #[error("invalid friendbot url: {0}")]
    InvalidUrl(String),
    #[error(transparent)]
    JsonRpc(#[from] jsonrpsee_core::Error),
    #[error("json decoding error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("transaction failed: {0}")]
    TransactionFailed(String),
    #[error("transaction submission failed: {0}")]
    TransactionSubmissionFailed(String),
    #[error("expected transaction status: {0}")]
    UnexpectedTransactionStatus(String),
    #[error("transaction submission timeout")]
    TransactionSubmissionTimeout,
    #[error("transaction simulation failed: {0}")]
    TransactionSimulationFailed(String),
    #[error("{0} not found: {1}")]
    NotFound(String, String),
    #[error("Missing result in successful response")]
    MissingResult,
    #[error("Failed to read Error response from server")]
    MissingError,
    #[error("Missing signing key for account {address}")]
    MissingSignerForAddress { address: String },
    #[error("cursor is not valid")]
    InvalidCursor,
    #[error("unexpected ({length}) simulate transaction result length")]
    UnexpectedSimulateTransactionResultSize { length: usize },
    #[error("unexpected ({count}) number of operations")]
    UnexpectedOperationCount { count: usize },
    #[error("Transaction contains unsupported operation type")]
    UnsupportedOperationType,
    #[error("unexpected contract code data type: {0:?}")]
    UnexpectedContractCodeDataType(LedgerEntryData),
    #[error("unexpected contract instance type: {0:?}")]
    UnexpectedContractInstance(xdr::ScVal),
    #[error("unexpected contract code got token {0:?}")]
    #[deprecated(note = "To be removed in future versions")]
    UnexpectedToken(ContractDataEntry),
    #[error("Fee was too large {0}")]
    LargeFee(u64),
    #[error("Cannot authorize raw transactions")]
    CannotAuthorizeRawTransaction,
    #[error("Missing result for tnx")]
    MissingOp,
}

fn from_xdr<T: ReadXdr>(x: &str) -> Result<T, xdr::Error> {
    T::from_xdr_base64(x, Limits::depth(MAX_DEPTH))
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct SendTransactionResponse {
    pub hash: String,
    pub status: String,
    #[serde(
        rename = "errorResultXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub error_result_xdr: Option<String>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(
        rename = "latestLedgerCloseTime",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger_close_time: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetTransactionResponseRaw {
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(
        rename = "latestLedgerCloseTime",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger_close_time: i64,
    #[serde(rename = "oldestLedger")]
    pub oldest_ledger: u32,
    #[serde(
        rename = "oldestLedgerCloseTime",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub oldest_ledger_close_time: u32,
    #[serde(flatten)]
    pub transaction_info: TransactionInfoRaw,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetTransactionResponse {
    pub latest_ledger: u32,
    pub latest_ledger_close_time: i64,
    pub oldest_ledger: u32,
    pub oldest_ledger_close_time: u32,
    pub transaction_info: TransactionInfo,
}

impl TryInto<GetTransactionResponse> for GetTransactionResponseRaw {
    type Error = xdr::Error;

    fn try_into(self) -> Result<GetTransactionResponse, Self::Error> {
        Ok(GetTransactionResponse {
            latest_ledger: self.latest_ledger,
            latest_ledger_close_time: self.latest_ledger_close_time,
            oldest_ledger: self.oldest_ledger,
            oldest_ledger_close_time: self.oldest_ledger_close_time,
            transaction_info: self.transaction_info.try_into()?,
        })
    }
}

impl GetTransactionResponse {
    ///
    /// # Errors
    pub fn return_value(&self) -> Result<xdr::ScVal, Error> {
        if let Some(xdr::TransactionMeta::V3(xdr::TransactionMetaV3 {
            soroban_meta: Some(xdr::SorobanTransactionMeta { return_value, .. }),
            ..
        })) = &self.transaction_info.result_meta
        {
            Ok(return_value.clone())
        } else {
            Err(Error::MissingOp)
        }
    }

    ///
    /// # Errors
    pub fn events(&self) -> Result<Vec<DiagnosticEvent>, Error> {
        self.transaction_info
            .result_meta
            .as_ref()
            .map(extract_events)
            .ok_or(Error::MissingOp)
    }

    ///
    /// # Errors
    pub fn contract_events(&self) -> Result<Vec<DiagnosticEvent>, Error> {
        Ok(self
            .events()?
            .into_iter()
            .filter(|e| matches!(e.event.type_, ContractEventType::Contract))
            .collect::<Vec<_>>())
    }

    pub fn result(&self) -> Option<&xdr::TransactionResult> {
        self.transaction_info.result.as_ref()
    }

    pub fn result_meta(&self) -> Option<&xdr::TransactionMeta> {
        self.transaction_info.result_meta.as_ref()
    }

    pub fn envelope(&self) -> Option<&xdr::TransactionEnvelope> {
        self.transaction_info.envelope.as_ref()
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct TransactionInfoRaw {
    pub status: String,
    #[serde(rename = "applicationOrder")]
    pub application_order: Option<i32>,
    #[serde(rename = "txHash", default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(rename = "feeBump")]
    pub fee_bump: Option<bool>,
    #[serde(
        rename = "envelopeXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub envelope_xdr: Option<String>,
    #[serde(rename = "resultXdr", skip_serializing_if = "Option::is_none", default)]
    pub result_xdr: Option<String>,
    #[serde(
        rename = "resultMetaXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub result_meta_xdr: Option<String>,
    #[serde(
        rename = "diagnosticEventsXdr",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub diagnostic_events_xdr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,
    #[serde(flatten)]
    pub close_time: Option<CloseTime>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum CloseTime {
    Protocol22 {
        #[serde(
            rename = "createdAt",
            deserialize_with = "deserialize_number_from_string"
        )]
        ledger_close_time: i64,
    },
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct TransactionInfo {
    pub status: String,
    pub application_order: Option<i32>,
    pub transaction_hash: Option<Hash>,
    pub fee_bump: bool,
    pub envelope: Option<xdr::TransactionEnvelope>,
    pub result: Option<xdr::TransactionResult>,
    pub result_meta: Option<xdr::TransactionMeta>,
    pub diagnostic_events_xdr: Vec<DiagnosticEvent>,
    pub ledger: Option<u32>,
    pub close_time: Option<CloseTime>,
}

impl TransactionInfo {
    pub fn ledger_close_time(&self) -> Option<i64> {
        self.close_time.as_ref().map(|d| match d {
            CloseTime::Protocol22 { ledger_close_time } => *ledger_close_time,
        })
    }
}

impl TryInto<TransactionInfo> for TransactionInfoRaw {
    type Error = xdr::Error;
    fn try_into(self) -> Result<TransactionInfo, Self::Error> {
        Ok(TransactionInfo {
            status: self.status,
            transaction_hash: self
                .transaction_hash
                .as_deref()
                .and_then(|x| (!x.is_empty()).then_some(x))
                .map(from_xdr)
                .transpose()?,
            fee_bump: self.fee_bump.unwrap_or_default(),
            envelope: self.envelope_xdr.as_deref().map(from_xdr).transpose()?,
            result: self.result_xdr.as_deref().map(from_xdr).transpose()?,
            result_meta: self.result_meta_xdr.as_deref().map(from_xdr).transpose()?,
            application_order: self.application_order,
            ledger: self.ledger,
            diagnostic_events_xdr: self
                .diagnostic_events_xdr
                .iter()
                .map(|event| from_xdr(event))
                .collect::<Result<Vec<_>, _>>()?,
            close_time: self.close_time,
        })
    }
}

#[serde_as]
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetTransactionsResponseRaw {
    pub transactions: Vec<TransactionInfoRaw>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "latestLedgerCloseTimestamp")]
    pub latest_ledger_close_time: i64,
    #[serde(rename = "oldestLedger")]
    pub oldest_ledger: u32,
    #[serde(rename = "oldestLedgerCloseTimestamp")]
    pub oldest_ledger_close_time: i64,
    #[serde_as(as = "DisplayFromStr")]
    pub cursor: u64,
}
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetTransactionsResponse {
    pub transactions: Vec<TransactionInfo>,
    pub latest_ledger: u32,
    pub latest_ledger_close_time: i64,
    pub oldest_ledger: u32,
    pub oldest_ledger_close_time: i64,
    pub cursor: u64,
}
impl TryInto<GetTransactionsResponse> for GetTransactionsResponseRaw {
    type Error = xdr::Error; // assuming xdr::Error or any other error type that you use

    fn try_into(self) -> Result<GetTransactionsResponse, Self::Error> {
        Ok(GetTransactionsResponse {
            transactions: self
                .transactions
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, xdr::Error>>()?,
            latest_ledger: self.latest_ledger,
            latest_ledger_close_time: self.latest_ledger_close_time,
            oldest_ledger: self.oldest_ledger,
            oldest_ledger_close_time: self.oldest_ledger_close_time,
            cursor: self.cursor,
        })
    }
}

#[serde_as]
#[derive(serde::Serialize, Debug, Clone)]
pub struct TransactionsPaginationOptions {
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct GetTransactionsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_ledger: Option<u32>,
    pub pagination: Option<TransactionsPaginationOptions>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct LedgerEntryResult {
    pub key: String,
    pub xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger: u32,
    #[serde(
        rename = "liveUntilLedgerSeq",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_option_number_from_string",
        default
    )]
    pub live_until_ledger_seq_ledger_seq: Option<u32>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetLedgerEntriesResponse {
    pub entries: Option<Vec<LedgerEntryResult>>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: i64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetNetworkResponse {
    #[serde(
        rename = "friendbotUrl",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub friendbot_url: Option<String>,
    pub passphrase: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetLatestLedgerResponse {
    pub id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    pub sequence: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct SimulateHostFunctionResultRaw {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub auth: Vec<String>,
    pub xdr: String,
}

#[derive(Debug, Clone)]
pub struct SimulateHostFunctionResult {
    pub auth: Vec<SorobanAuthorizationEntry>,
    pub xdr: xdr::ScVal,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum LedgerEntryChange {
    #[serde(rename = "created")]
    Created { key: String, after: String },
    #[serde(rename = "deleted")]
    Deleted { key: String, before: String },
    #[serde(rename = "updated")]
    Updated {
        key: String,
        before: String,
        after: String,
    },
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, Clone)]
pub struct SimulateTransactionResponse {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    #[serde(rename = "transactionData", default)]
    pub transaction_data: String,
    #[serde(
        deserialize_with = "deserialize_default_from_null",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub events: Vec<String>,
    #[serde(
        rename = "minResourceFee",
        deserialize_with = "deserialize_number_from_string",
        default
    )]
    pub min_resource_fee: u64,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub results: Vec<SimulateHostFunctionResultRaw>,
    #[serde(
        rename = "restorePreamble",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub restore_preamble: Option<RestorePreamble>,
    #[serde(
        rename = "stateChanges",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub state_changes: Option<Vec<LedgerEntryChange>>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
}

impl SimulateTransactionResponse {
    ///
    /// # Errors
    pub fn results(&self) -> Result<Vec<SimulateHostFunctionResult>, Error> {
        self.results
            .iter()
            .map(|r| {
                Ok(SimulateHostFunctionResult {
                    auth: r
                        .auth
                        .iter()
                        .map(Deref::deref)
                        .map(from_xdr)
                        .collect::<Result<_, xdr::Error>>()?,
                    xdr: from_xdr(&r.xdr)?,
                })
            })
            .collect()
    }

    ///
    /// # Errors
    pub fn events(&self) -> Result<Vec<DiagnosticEvent>, Error> {
        self.events.iter().map(|e| Ok(from_xdr(e)?)).collect()
    }

    ///
    /// # Errors
    pub fn transaction_data(&self) -> Result<SorobanTransactionData, Error> {
        Ok(from_xdr(&self.transaction_data)?)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, Clone)]
pub struct RestorePreamble {
    #[serde(rename = "transactionData")]
    pub transaction_data: String,
    #[serde(
        rename = "minResourceFee",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub min_resource_fee: u64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetEventsResponseRaw {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub events: Vec<EventRaw>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    pub cursor: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetEventsResponse {
    pub events: Vec<Event>,
    pub latest_ledger: u32,
    pub cursor: Option<String>,
}

impl TryInto<GetEventsResponse> for GetEventsResponseRaw {
    type Error = xdr::Error;

    fn try_into(self) -> Result<GetEventsResponse, Self::Error> {
        Ok(GetEventsResponse {
            events: self
                .events
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            latest_ledger: self.latest_ledger,
            cursor: self.cursor,
        })
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetVersionInfoResponse {
    pub version: String,
    #[serde(rename = "commitHash")]
    pub commit_hash: String,
    #[serde(rename = "buildTimestamp")]
    pub build_timestamp: String,
    #[serde(rename = "captiveCoreVersion")]
    pub captive_core_version: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
}

// Determines whether or not a particular filter matches a topic based on the
// same semantics as the RPC server:
//
//  - for an exact segment match, the filter is a base64-encoded ScVal
//  - for a wildcard, single-segment match, the string "*" matches exactly one
//    segment
//
// The expectation is that a `filter` is a comma-separated list of segments that
// has previously been validated, and `topic` is the list of segments applicable
// for this event.
//
// [API
// Reference](https://docs.google.com/document/d/1TZUDgo_3zPz7TiPMMHVW_mtogjLyPL0plvzGMsxSz6A/edit#bookmark=id.35t97rnag3tx)
// [Code
// Reference](https://github.com/stellar/soroban-tools/blob/bac1be79e8c2590c9c35ad8a0168aab0ae2b4171/cmd/soroban-rpc/internal/methods/get_events.go#L182-L203)
#[must_use]
pub fn does_topic_match(topic: &[String], filter: &[String]) -> bool {
    filter.len() == topic.len()
        && filter
            .iter()
            .enumerate()
            .all(|(i, s)| *s == "*" || topic[i] == *s)
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct EventRaw {
    #[serde(rename = "type")]
    pub event_type: String,
    pub ledger: u32,
    #[serde(rename = "ledgerClosedAt")]
    pub ledger_closed_at: String,
    #[serde(rename = "contractId")]
    pub contract_id: String,
    pub id: String,
    #[serde(rename = "inSuccessfulContractCall")]
    pub in_successful_contract_call: bool,
    #[serde(rename = "txHash")]
    pub transaction_hash: String,
    pub topic: Vec<String>,
    pub value: String,
    /// Deprecated
    #[serde(rename = "pagingToken")]
    pub paging_token: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct Event {
    pub event_type: String,
    pub ledger: u32,
    pub ledger_closed_at: String,
    pub contract_id: String,
    pub id: String,
    pub paging_token: Option<String>,
    pub topic: Vec<ScVal>,
    pub value: ScVal,
    pub in_successful_contract_call: bool,
    pub transaction_hash: Hash,
}

impl TryInto<Event> for EventRaw {
    type Error = xdr::Error;

    fn try_into(self) -> Result<Event, Self::Error> {
        Ok(Event {
            event_type: self.event_type,
            ledger: self.ledger,
            ledger_closed_at: self.ledger_closed_at,
            contract_id: self.contract_id,
            id: self.id,
            paging_token: self.paging_token,
            topic: self
                .topic
                .iter()
                .map(Deref::deref)
                .map(from_xdr)
                .collect::<Result<_, _>>()?,
            value: from_xdr(&self.value)?,
            in_successful_contract_call: self.in_successful_contract_call,
            transaction_hash: self.transaction_hash.parse()?,
        })
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            id,
            ledger,
            ledger_closed_at,
            contract_id,
            value,
            ..
        } = self;
        writeln!(f, "Event {id} [{}]:", self.event_type.to_ascii_uppercase())?;
        writeln!(f, "  Ledger:   {ledger} (closed at {ledger_closed_at})",)?;
        writeln!(f, "  Contract: {contract_id}")?;
        writeln!(f, "  Topics:")?;
        for topic in &self.topic {
            writeln!(f, "            {topic:?}")?;
        }
        writeln!(f, "  Value:    {value:?}")
    }
}

impl Event {
    ///
    /// # Errors
    pub fn parse_cursor(&self) -> Result<(u64, i32), Error> {
        parse_cursor(&self.id)
    }
    ///
    /// # Errors
    pub fn pretty_print(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut stdout = StandardStream::stdout(ColorChoice::Auto);
        if !stdout.supports_color() {
            println!("{self}");
            return Ok(());
        }

        let color = match self.event_type.as_str() {
            "system" => Color::Yellow,
            _ => Color::Blue,
        };
        colored!(
            stdout,
            "{}Event{} {}{}{} [{}{}{}{}]:\n",
            bold!(true),
            bold!(false),
            fg!(Some(Color::Green)),
            self.id,
            reset!(),
            bold!(true),
            fg!(Some(color)),
            self.event_type.to_ascii_uppercase(),
            reset!(),
        )?;

        colored!(
            stdout,
            "  Ledger:   {}{}{} (closed at {}{}{})\n",
            fg!(Some(Color::Green)),
            self.ledger,
            reset!(),
            fg!(Some(Color::Green)),
            self.ledger_closed_at,
            reset!(),
        )?;

        colored!(
            stdout,
            "  Contract: {}{}{}\n",
            fg!(Some(Color::Green)),
            self.contract_id,
            reset!(),
        )?;

        colored!(stdout, "  Topics:\n")?;
        for topic in &self.topic {
            colored!(
                stdout,
                "            {}{:?}{}\n",
                fg!(Some(Color::Green)),
                topic,
                reset!(),
            )?;
        }

        colored!(
            stdout,
            "  Value: {}{:?}{}\n",
            fg!(Some(Color::Green)),
            self.value,
            reset!(),
        )?;

        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, clap::ValueEnum)]
pub enum EventType {
    All,
    Contract,
    System,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EventStart {
    Ledger(u32),
    Cursor(String),
}

#[derive(Debug, Clone)]
pub struct FullLedgerEntry {
    pub key: LedgerKey,
    pub val: LedgerEntryData,
    pub last_modified_ledger: u32,
    pub live_until_ledger_seq: u32,
}

#[derive(Debug, Clone)]
pub struct FullLedgerEntries {
    pub entries: Vec<FullLedgerEntry>,
    pub latest_ledger: i64,
}

#[derive(Debug, Clone)]
pub struct Client {
    base_url: Arc<str>,
    timeout_in_secs: u64,
    http_client: Arc<HttpClient>,
}

#[allow(deprecated)] // Can be removed once Client doesn't have any code marked deprecated inside
impl Client {
    ///
    /// # Errors
    pub fn new(base_url: &str) -> Result<Self, Error> {
        // Add the port to the base URL if there is no port explicitly included
        // in the URL and the scheme allows us to infer a default port.
        // Jsonrpsee requires a port to always be present even if one can be
        // inferred. This may change: https://github.com/paritytech/jsonrpsee/issues/1048.
        let uri = base_url.parse::<Uri>().map_err(Error::InvalidRpcUrl)?;
        let mut parts = uri.into_parts();
        if let (Some(scheme), Some(authority)) = (&parts.scheme, &parts.authority) {
            if authority.port().is_none() {
                let port = match scheme.as_str() {
                    "http" => Some(80),
                    "https" => Some(443),
                    _ => None,
                };
                if let Some(port) = port {
                    let host = authority.host();
                    parts.authority = Some(
                        Authority::from_str(&format!("{host}:{port}"))
                            .map_err(Error::InvalidRpcUrl)?,
                    );
                }
            }
        }
        let uri = Uri::from_parts(parts).map_err(Error::InvalidRpcUrlFromUriParts)?;
        let base_url = Arc::from(uri.to_string());
        tracing::trace!(?uri);
        let mut headers = HeaderMap::new();
        headers.insert("X-Client-Name", unsafe {
            "soroban-cli".parse().unwrap_unchecked()
        });
        let version = VERSION.unwrap_or("devel");
        headers.insert("X-Client-Version", unsafe {
            version.parse().unwrap_unchecked()
        });
        let http_client = Arc::new(
            HttpClientBuilder::default()
                .set_headers(headers)
                .build(&base_url)?,
        );
        Ok(Self {
            base_url,
            timeout_in_secs: 30,
            http_client,
        })
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Create a new client with a timeout in seconds
    /// # Errors
    pub fn new_with_timeout(base_url: &str, timeout: u64) -> Result<Self, Error> {
        let mut client = Self::new(base_url)?;
        client.timeout_in_secs = timeout;
        Ok(client)
    }

    #[must_use]
    pub fn client(&self) -> &HttpClient {
        &self.http_client
    }

    ///
    /// # Errors
    pub async fn friendbot_url(&self) -> Result<String, Error> {
        let network = self.get_network().await?;
        tracing::trace!("{network:#?}");
        network.friendbot_url.ok_or_else(|| {
            Error::NotFound(
                "Friendbot".to_string(),
                "Friendbot is not available on this network".to_string(),
            )
        })
    }
    ///
    /// # Errors
    pub async fn verify_network_passphrase(&self, expected: Option<&str>) -> Result<String, Error> {
        let server = self.get_network().await?.passphrase;
        if let Some(expected) = expected {
            if expected != server {
                return Err(Error::InvalidNetworkPassphrase {
                    expected: expected.to_string(),
                    server,
                });
            }
        }
        Ok(server)
    }

    ///
    /// # Errors
    pub async fn get_network(&self) -> Result<GetNetworkResponse, Error> {
        tracing::trace!("Getting network");
        Ok(self
            .client()
            .request("getNetwork", ObjectParams::new())
            .await?)
    }

    ///
    /// # Errors
    pub async fn get_latest_ledger(&self) -> Result<GetLatestLedgerResponse, Error> {
        tracing::trace!("Getting latest ledger");
        Ok(self
            .client()
            .request("getLatestLedger", ObjectParams::new())
            .await?)
    }

    ///
    /// # Errors
    pub async fn get_account(&self, address: impl Into<AccountId>) -> Result<AccountEntry, Error> {
        let account_id = address.into();
        tracing::trace!("Getting address {}", account_id);
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: account_id.clone(),
        });
        let keys = Vec::from([key]);
        let response = self.get_ledger_entries(&keys).await?;
        let entries = response.entries.unwrap_or_default();
        if entries.is_empty() {
            return Err(Error::NotFound(
                "Account".to_string(),
                account_id.to_string(),
            ));
        }
        if let LedgerEntryData::Account(entry) = from_xdr(&entries[0].xdr)? {
            tracing::trace!(account=?entry);
            Ok(entry)
        } else {
            Err(Error::InvalidResponse)
        }
    }

    /// Send a transaction to the network and get back the hash of the transaction.
    /// # Errors
    pub async fn send_transaction(&self, tx: &TransactionEnvelope) -> Result<Hash, Error> {
        tracing::trace!("Sending:\n{tx:#?}");
        let mut oparams = ObjectParams::new();
        oparams.insert("transaction", tx.to_xdr_base64(Limits::none())?)?;
        let SendTransactionResponse {
            hash,
            error_result_xdr,
            status,
            ..
        } = self
            .client()
            .request("sendTransaction", oparams)
            .await
            .map_err(|err| {
                Error::TransactionSubmissionFailed(format!("No status yet:\n {err:#?}"))
            })?;

        if status == "ERROR" {
            let error = error_result_xdr
                .as_deref()
                .ok_or(Error::MissingError)
                .and_then(|x| from_xdr::<TransactionResult>(x).map_err(|_| Error::InvalidResponse))
                .map(|r| r.result);
            tracing::error!("TXN {hash} failed:\n {error:#?}");
            return Err(Error::TransactionSubmissionFailed(format!("{:#?}", error?)));
        }
        Ok(Hash::from_str(&hash)?)
    }

    ///
    /// # Errors
    pub async fn send_transaction_polling(
        &self,
        tx: &TransactionEnvelope,
    ) -> Result<GetTransactionResponse, Error> {
        let hash = self.send_transaction(tx).await?;
        self.get_transaction_polling(&hash, None).await
    }

    ///
    /// # Errors
    pub async fn simulate_transaction_envelope(
        &self,
        tx: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, Error> {
        tracing::trace!("Simulating:\n{tx:#?}");
        let base64_tx = tx.to_xdr_base64(Limits::none())?;
        let mut oparams = ObjectParams::new();
        oparams.insert("transaction", base64_tx)?;
        let sim_res = self
            .client()
            .request("simulateTransaction", oparams)
            .await?;
        tracing::trace!("Simulation response:\n {sim_res:#?}");
        Ok(sim_res)
    }

    ///
    /// # Errors
    pub async fn get_transaction(&self, tx_id: &Hash) -> Result<GetTransactionResponse, Error> {
        let mut oparams = ObjectParams::new();
        oparams.insert("hash", tx_id)?;
        let resp: GetTransactionResponseRaw =
            self.client().request("getTransaction", oparams).await?;
        Ok(resp.try_into()?)
    }

    ///
    /// # Errors
    pub async fn get_transactions(
        &self,
        request: GetTransactionsRequest,
    ) -> Result<GetTransactionsResponse, Error> {
        let mut oparams = ObjectParams::new();
        if let Some(start_ledger) = request.start_ledger {
            oparams.insert("startLedger", start_ledger)?;
        }
        if let Some(pagination_params) = request.pagination {
            let pagination = serde_json::json!(pagination_params);
            oparams.insert("pagination", pagination)?;
        }
        let resp: GetTransactionsResponseRaw =
            self.client().request("getTransactions", oparams).await?;
        Ok(resp.try_into()?)
    }

    /// Poll the transaction status. Can provide a timeout in seconds, otherwise uses the default timeout.
    ///
    /// It uses exponential backoff with a base of 1 second and a maximum of 30 seconds.
    ///
    /// # Errors
    /// - `Error::TransactionSubmissionTimeout` if the transaction status is not found within the timeout
    /// - `Error::TransactionSubmissionFailed` if the transaction status is "FAILED"
    /// - `Error::UnexpectedTransactionStatus` if the transaction status is not one of "SUCCESS", "FAILED", or ``NOT_FOUND``
    /// - `json_rpsee` Errors
    pub async fn get_transaction_polling(
        &self,
        tx_id: &Hash,
        timeout_s: Option<Duration>,
    ) -> Result<GetTransactionResponse, Error> {
        // Poll the transaction status
        let start = Instant::now();
        let timeout = timeout_s.unwrap_or(Duration::from_secs(self.timeout_in_secs));
        // see https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=50731
        // Is optimimal exponent for expontial backoff
        let exponential_backoff: f64 = 1.0 / (1.0 - E.powf(-1.0));
        let mut sleep_time = Duration::from_secs(1);
        loop {
            let response = self.get_transaction(tx_id).await?;
            match response.transaction_info.status.as_str() {
                "SUCCESS" => {
                    // TODO: the caller should probably be printing this
                    tracing::trace!("{response:#?}");
                    return Ok(response);
                }
                "FAILED" => {
                    tracing::error!("{response:#?}");
                    // TODO: provide a more elaborate error
                    return Err(Error::TransactionSubmissionFailed(format!(
                        "{:#?}",
                        response.transaction_info.result
                    )));
                }
                "NOT_FOUND" => (),
                _ => {
                    return Err(Error::UnexpectedTransactionStatus(
                        response.transaction_info.status,
                    ));
                }
            };
            if start.elapsed() > timeout {
                return Err(Error::TransactionSubmissionTimeout);
            }
            sleep(sleep_time).await;
            sleep_time = Duration::from_secs_f64(sleep_time.as_secs_f64() * exponential_backoff);
        }
    }

    ///
    /// # Errors
    pub async fn get_ledger_entries(
        &self,
        keys: &[LedgerKey],
    ) -> Result<GetLedgerEntriesResponse, Error> {
        let base64_keys = keys
            .iter()
            .map(|k| k.to_xdr_base64(Limits::none()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut oparams = ObjectParams::new();
        oparams.insert("keys", base64_keys)?;
        Ok(self.client().request("getLedgerEntries", oparams).await?)
    }

    ///
    /// # Errors
    pub async fn get_full_ledger_entries(
        &self,
        ledger_keys: &[LedgerKey],
    ) -> Result<FullLedgerEntries, Error> {
        let keys = ledger_keys
            .iter()
            .filter(|key| !matches!(key, LedgerKey::Ttl(_)))
            .map(Clone::clone)
            .collect::<Vec<_>>();
        tracing::trace!("keys: {keys:#?}");
        let GetLedgerEntriesResponse {
            entries,
            latest_ledger,
        } = self.get_ledger_entries(&keys).await?;
        tracing::trace!("raw: {entries:#?}");
        let entries = entries
            .unwrap_or_default()
            .iter()
            .map(
                |LedgerEntryResult {
                     key,
                     xdr,
                     last_modified_ledger,
                     live_until_ledger_seq_ledger_seq,
                 }| {
                    Ok(FullLedgerEntry {
                        key: from_xdr(key)?,
                        val: from_xdr(xdr)?,
                        live_until_ledger_seq: live_until_ledger_seq_ledger_seq.unwrap_or_default(),
                        last_modified_ledger: *last_modified_ledger,
                    })
                },
            )
            .collect::<Result<Vec<_>, Error>>()?;
        tracing::trace!("parsed: {entries:#?}");
        Ok(FullLedgerEntries {
            entries,
            latest_ledger,
        })
    }
    ///
    /// # Errors
    pub async fn get_events(
        &self,
        start: EventStart,
        event_type: Option<EventType>,
        contract_ids: &[String],
        topics: &[String],
        limit: Option<usize>,
    ) -> Result<GetEventsResponse, Error> {
        let mut filters = serde_json::Map::new();

        event_type
            .and_then(|t| match t {
                EventType::All => None, // all is the default, so avoid incl. the param
                EventType::Contract => Some("contract"),
                EventType::System => Some("system"),
            })
            .map(|t| filters.insert("type".to_string(), t.into()));

        filters.insert("topics".to_string(), topics.into());
        filters.insert("contractIds".to_string(), contract_ids.into());

        let mut pagination = serde_json::Map::new();
        if let Some(limit) = limit {
            pagination.insert("limit".to_string(), limit.into());
        }

        let mut oparams = ObjectParams::new();
        match start {
            EventStart::Ledger(l) => oparams.insert("startLedger", l)?,
            EventStart::Cursor(c) => {
                pagination.insert("cursor".to_string(), c.into());
            }
        };
        oparams.insert("filters", vec![filters])?;
        oparams.insert("pagination", pagination)?;
        let resp: GetEventsResponseRaw = self.client().request("getEvents", oparams).await?;
        Ok(resp.try_into()?)
    }

    ///
    /// # Errors
    pub async fn get_contract_data(
        &self,
        contract_id: &[u8; 32],
    ) -> Result<ContractDataEntry, Error> {
        // Get the contract from the network
        let contract_key = LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: xdr::ScAddress::Contract(xdr::Hash(*contract_id)),
            key: xdr::ScVal::LedgerKeyContractInstance,
            durability: xdr::ContractDataDurability::Persistent,
        });
        let contract_ref = self.get_ledger_entries(&[contract_key]).await?;
        let entries = contract_ref.entries.unwrap_or_default();
        if entries.is_empty() {
            let contract_address = stellar_strkey::Contract(*contract_id).to_string();
            return Err(Error::NotFound("Contract".to_string(), contract_address));
        }
        let contract_ref_entry = &entries[0];
        match from_xdr::<LedgerEntryData>(&contract_ref_entry.xdr)? {
            LedgerEntryData::ContractData(contract_data) => Ok(contract_data),
            scval => Err(Error::UnexpectedContractCodeDataType(scval)),
        }
    }

    ///
    /// # Errors
    #[deprecated(note = "To be removed in future versions, use get_ledger_entries()")]
    pub async fn get_remote_wasm(&self, contract_id: &[u8; 32]) -> Result<Vec<u8>, Error> {
        match self.get_contract_data(contract_id).await? {
            xdr::ContractDataEntry {
                val:
                    xdr::ScVal::ContractInstance(xdr::ScContractInstance {
                        executable: xdr::ContractExecutable::Wasm(hash),
                        ..
                    }),
                ..
            } => self.get_remote_wasm_from_hash(hash).await,
            scval => Err(Error::UnexpectedToken(scval)),
        }
    }

    ///
    /// # Errors
    #[deprecated(note = "To be removed in future versions, use get_ledger_entries()")]
    pub async fn get_remote_wasm_from_hash(&self, hash: Hash) -> Result<Vec<u8>, Error> {
        let code_key = LedgerKey::ContractCode(xdr::LedgerKeyContractCode { hash: hash.clone() });
        let contract_data = self.get_ledger_entries(&[code_key]).await?;
        let entries = contract_data.entries.unwrap_or_default();
        if entries.is_empty() {
            return Err(Error::NotFound(
                "Contract Code".to_string(),
                hex::encode(hash),
            ));
        }
        let contract_data_entry = &entries[0];
        match from_xdr::<LedgerEntryData>(&contract_data_entry.xdr)? {
            LedgerEntryData::ContractCode(xdr::ContractCodeEntry { code, .. }) => Ok(code.into()),
            scval => Err(Error::UnexpectedContractCodeDataType(scval)),
        }
    }

    /// Get the contract instance from the network. Could be normal contract or native Stellar Asset Contract (SAC)
    ///
    /// # Errors
    /// - Could fail to find contract or have a network error
    pub async fn get_contract_instance(
        &self,
        contract_id: &[u8; 32],
    ) -> Result<ScContractInstance, Error> {
        let contract_data = self.get_contract_data(contract_id).await?;
        match contract_data.val {
            xdr::ScVal::ContractInstance(instance) => Ok(instance),
            scval => Err(Error::UnexpectedContractInstance(scval)),
        }
    }

    /// Get Version Info
    /// # Errors
    /// - Could fail to get version info or have a network error
    pub async fn get_version_info(&self) -> Result<GetVersionInfoResponse, Error> {
        Ok(self
            .client()
            .request("getVersionInfo", ObjectParams::new())
            .await?)
    }
}

fn extract_events(tx_meta: &TransactionMeta) -> Vec<DiagnosticEvent> {
    match tx_meta {
        TransactionMeta::V3(TransactionMetaV3 {
            soroban_meta: Some(meta),
            ..
        }) => {
            // NOTE: we assume there can only be one operation, since we only send one
            if meta.diagnostic_events.len() == 1 {
                meta.diagnostic_events.clone().into()
            } else if meta.events.len() == 1 {
                meta.events
                    .iter()
                    .map(|e| DiagnosticEvent {
                        in_successful_contract_call: true,
                        event: e.clone(),
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

pub(crate) fn parse_cursor(c: &str) -> Result<(u64, i32), Error> {
    let (toid_part, event_index) = c.split('-').collect_tuple().ok_or(Error::InvalidCursor)?;
    let toid_part: u64 = toid_part.parse().map_err(|_| Error::InvalidCursor)?;
    let start_index: i32 = event_index.parse().map_err(|_| Error::InvalidCursor)?;
    Ok((toid_part, start_index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn simulation_transaction_response_parsing() {
        let s = r#"{
 "minResourceFee": "100000000",
 "cost": { "cpuInsns": "1000", "memBytes": "1000" },
 "transactionData": "",
 "latestLedger": 1234,
 "stateChanges": [{
    "type": "created",
    "key": "AAAAAAAAAABuaCbVXZ2DlXWarV6UxwbW3GNJgpn3ASChIFp5bxSIWg==",
    "before": null,
    "after": "AAAAZAAAAAAAAAAAbmgm1V2dg5V1mq1elMcG1txjSYKZ9wEgoSBaeW8UiFoAAAAAAAAAZAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  }]
  }"#;

        let resp: SimulateTransactionResponse = serde_json::from_str(s).unwrap();
        assert_eq!(
            resp.state_changes.unwrap()[0],
            LedgerEntryChange::Created { key: "AAAAAAAAAABuaCbVXZ2DlXWarV6UxwbW3GNJgpn3ASChIFp5bxSIWg==".to_string(), after: "AAAAZAAAAAAAAAAAbmgm1V2dg5V1mq1elMcG1txjSYKZ9wEgoSBaeW8UiFoAAAAAAAAAZAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string() },
        );
        assert_eq!(resp.min_resource_fee, 100_000_000);
    }

    #[test]
    fn simulation_transaction_response_parsing_mostly_empty() {
        let s = r#"{
 "latestLedger": 1234
        }"#;

        let resp: SimulateTransactionResponse = serde_json::from_str(s).unwrap();
        assert_eq!(resp.latest_ledger, 1_234);
    }

    fn get_repo_root() -> PathBuf {
        let mut path = env::current_exe().expect("Failed to get current executable path");
        // Navigate up the directory tree until we find the repository root
        while path.pop() {
            if path.join("Cargo.toml").exists() {
                return path;
            }
        }
        panic!("Could not find repository root");
    }

    fn read_fixture_file<T: jsonrpsee_core::DeserializeOwned>(filename: &str) -> T {
        let repo_root = get_repo_root();
        let fixture_path = repo_root.join("src").join("fixtures").join(filename);
        let response_content: String =
            fs::read_to_string(fixture_path).expect("Failed to read fixture file");
        // Parse the entire response
        let full_response: serde_json::Value = serde_json::from_str(&response_content)
            .unwrap_or_else(|_| panic!("Failed to parse JSON from {filename}"));

        // Extract the "result" field
        let result = full_response["result"].clone();
        // Parse the "result" content as GetTransactionsResponseRaw
        serde_json::from_value(result).expect("Failed to parse 'result'")
    }

    #[test]
    fn parse_get_transactions_response() {
        let raw_response: GetTransactionsResponseRaw =
            read_fixture_file("curr_transactions_response.json");
        // Convert GetTransactionsResponseRaw to GetTransactionsResponse
        let response: GetTransactionsResponse = raw_response
            .try_into()
            .expect("Failed to convert GetTransactionsResponseRaw to GetTransactionsResponse");

        // Assertions
        assert_eq!(response.transactions.len(), 5);
        assert_eq!(response.latest_ledger, 556_962);
        assert_eq!(response.cursor, 2_379_420_471_922_689);

        // Additional assertions for specific transaction attributes
        assert_eq!(response.transactions[0].status, "SUCCESS");
        assert_eq!(response.transactions[0].application_order, Some(1));
        assert_eq!(response.transactions[0].ledger, Some(554_000));
        assert_eq!(
            response.transactions[0].ledger_close_time(),
            Some(1_721_053_660)
        );
    }

    #[test]
    fn parse_get_transaction_response() {
        // Parse the "result" content as GetTransactionsResponseRaw
        let raw_response: GetTransactionResponseRaw =
            read_fixture_file("curr_transaction_response.json");
        // Convert GetTransactionsResponseRaw to GetTransactionsResponse
        let response: GetTransactionResponse = raw_response
            .try_into()
            .expect("Failed to convert GetTransactionsResponseRaw to GetTransactionsResponse");
        assert_eq!(response.transaction_info.diagnostic_events_xdr.len(), 21);
        assert_eq!(response.transaction_info.status, "SUCCESS");
        assert_eq!(response.transaction_info.application_order, Some(251));
        assert_eq!(
            response.transaction_info.ledger_close_time(),
            Some(1_728_063_066)
        );
        assert_eq!(response.latest_ledger, 53_794_558);
        assert_eq!(response.oldest_ledger, 53_777_279);
        assert_eq!(response.oldest_ledger_close_time, 1_727_963_878);
        assert_eq!(response.latest_ledger_close_time, 1_728_063_258);
        assert_eq!(response.transaction_info.ledger, Some(53_794_524));
    }

    #[test]
    fn parse_new_get_transaction_response() {
        // Parse the "result" content as GetTransactionsResponseRaw
        let raw_response: GetTransactionResponseRaw =
            read_fixture_file("new_transaction_response.json");
        println!("{raw_response:#?}");
        // Convert GetTransactionsResponseRaw to GetTransactionsResponse
        let response: GetTransactionResponse = raw_response
            .try_into()
            .expect("Failed to convert GetTransactionsResponseRaw to GetTransactionsResponse");
        assert_eq!(response.transaction_info.diagnostic_events_xdr.len(), 21);
        assert_eq!(response.transaction_info.status, "SUCCESS");
        assert_eq!(response.transaction_info.application_order, Some(1));
        assert_eq!(
            response.transaction_info.ledger_close_time(),
            Some(1_728_668_111)
        );
        assert_eq!(response.latest_ledger, 525);
        assert_eq!(response.oldest_ledger, 8);
        assert_eq!(response.oldest_ledger_close_time, 1_728_667_648);
        assert_eq!(response.latest_ledger_close_time, 1_728_668_165);
        assert_eq!(response.transaction_info.ledger, Some(471));
        assert!(!response.transaction_info.fee_bump);
        assert!(response.transaction_info.transaction_hash.is_none());
    }

    #[test]
    fn parse_curr_simulation_response() {
        let raw_response: SimulateTransactionResponse =
            read_fixture_file("curr_simulation_response.json");
        assert_eq!(raw_response.min_resource_fee, 92487);
        assert_eq!(raw_response.latest_ledger, 53_795_023);
        assert_eq!(raw_response.results.len(), 1);
        assert_eq!(raw_response.events().unwrap().len(), 2);
    }

    #[test]
    fn parse_new_get_events_response() {
        let raw_response: GetEventsResponseRaw = read_fixture_file("new_event_response.json");
        let response: GetEventsResponse = raw_response.try_into().unwrap();
        assert_eq!(response.latest_ledger, 3266);
        assert_eq!(response.cursor.as_deref(), Some("0000012859132096512-0000000017"));
        assert_eq!(response.events.len(), 100);
    }

    #[test]
    fn rpc_url_default_ports() {
        // Default ports are added.
        let client = Client::new("http://example.com").unwrap();
        assert_eq!(client.base_url(), "http://example.com:80/");
        let client = Client::new("https://example.com").unwrap();
        assert_eq!(client.base_url(), "https://example.com:443/");

        // Ports are not added when already present.
        let client = Client::new("http://example.com:8080").unwrap();
        assert_eq!(client.base_url(), "http://example.com:8080/");
        let client = Client::new("https://example.com:8080").unwrap();
        assert_eq!(client.base_url(), "https://example.com:8080/");

        // Paths are not modified.
        let client = Client::new("http://example.com/a/b/c").unwrap();
        assert_eq!(client.base_url(), "http://example.com:80/a/b/c");
        let client = Client::new("https://example.com/a/b/c").unwrap();
        assert_eq!(client.base_url(), "https://example.com:443/a/b/c");
        let client = Client::new("http://example.com/a/b/c/").unwrap();
        assert_eq!(client.base_url(), "http://example.com:80/a/b/c/");
        let client = Client::new("https://example.com/a/b/c/").unwrap();
        assert_eq!(client.base_url(), "https://example.com:443/a/b/c/");
        let client = Client::new("http://example.com/a/b:80/c/").unwrap();
        assert_eq!(client.base_url(), "http://example.com:80/a/b:80/c/");
        let client = Client::new("https://example.com/a/b:80/c/").unwrap();
        assert_eq!(client.base_url(), "https://example.com:443/a/b:80/c/");
    }

    #[test]
    // Taken from [RPC server
    // tests](https://github.com/stellar/soroban-tools/blob/main/cmd/soroban-rpc/internal/methods/get_events_test.go#L21).
    fn topic_match() {
        struct TestCase<'a> {
            name: &'a str,
            filter: Vec<&'a str>,
            includes: Vec<Vec<&'a str>>,
            excludes: Vec<Vec<&'a str>>,
        }

        let xfer = "AAAABQAAAAh0cmFuc2Zlcg==";
        let number = "AAAAAQB6Mcc=";
        let star = "*";

        for tc in vec![
            // No filter means match nothing.
            TestCase {
                name: "<empty>",
                filter: vec![],
                includes: vec![],
                excludes: vec![vec![xfer]],
            },
            // "*" should match "transfer/" but not "transfer/transfer" or
            // "transfer/amount", because * is specified as a SINGLE segment
            // wildcard.
            TestCase {
                name: "*",
                filter: vec![star],
                includes: vec![vec![xfer]],
                excludes: vec![vec![xfer, xfer], vec![xfer, number]],
            },
            // "*/transfer" should match anything preceding "transfer", but
            // nothing that isn't exactly two segments long.
            TestCase {
                name: "*/transfer",
                filter: vec![star, xfer],
                includes: vec![vec![number, xfer], vec![xfer, xfer]],
                excludes: vec![
                    vec![number],
                    vec![number, number],
                    vec![number, xfer, number],
                    vec![xfer],
                    vec![xfer, number],
                    vec![xfer, xfer, xfer],
                ],
            },
            // The inverse case of before: "transfer/*" should match any single
            // segment after a segment that is exactly "transfer", but no
            // additional segments.
            TestCase {
                name: "transfer/*",
                filter: vec![xfer, star],
                includes: vec![vec![xfer, number], vec![xfer, xfer]],
                excludes: vec![
                    vec![number],
                    vec![number, number],
                    vec![number, xfer, number],
                    vec![xfer],
                    vec![number, xfer],
                    vec![xfer, xfer, xfer],
                ],
            },
            // Here, we extend to exactly two wild segments after transfer.
            TestCase {
                name: "transfer/*/*",
                filter: vec![xfer, star, star],
                includes: vec![vec![xfer, number, number], vec![xfer, xfer, xfer]],
                excludes: vec![
                    vec![number],
                    vec![number, number],
                    vec![number, xfer],
                    vec![number, xfer, number, number],
                    vec![xfer],
                    vec![xfer, xfer, xfer, xfer],
                ],
            },
            // Here, we ensure wildcards can be in the middle of a filter: only
            // exact matches happen on the ends, while the middle can be
            // anything.
            TestCase {
                name: "transfer/*/number",
                filter: vec![xfer, star, number],
                includes: vec![vec![xfer, number, number], vec![xfer, xfer, number]],
                excludes: vec![
                    vec![number],
                    vec![number, number],
                    vec![number, number, number],
                    vec![number, xfer, number],
                    vec![xfer],
                    vec![number, xfer],
                    vec![xfer, xfer, xfer],
                    vec![xfer, number, xfer],
                ],
            },
        ] {
            for topic in tc.includes {
                assert!(
                    does_topic_match(
                        &topic
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<String>>(),
                        &tc.filter
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<String>>()
                    ),
                    "test: {}, topic ({:?}) should be matched by filter ({:?})",
                    tc.name,
                    topic,
                    tc.filter
                );
            }

            for topic in tc.excludes {
                assert!(
                    !does_topic_match(
                        // make deep copies of the vecs
                        &topic
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<String>>(),
                        &tc.filter
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect::<Vec<String>>()
                    ),
                    "test: {}, topic ({:?}) should NOT be matched by filter ({:?})",
                    tc.name,
                    topic,
                    tc.filter
                );
            }
        }
    }
}
