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
    self as xdr, AccountEntry, AccountId, ContractDataEntry, ContractEvent, ContractId,
    DiagnosticEvent, Error as XdrError, Hash, LedgerCloseMeta, LedgerEntryData, LedgerFootprint,
    LedgerHeaderHistoryEntry, LedgerKey, LedgerKeyAccount, Limited, Limits, PublicKey, ReadXdr,
    ScContractInstance, SorobanAuthorizationEntry, SorobanResources, SorobanTransactionData,
    TransactionEnvelope, TransactionEvent, TransactionMetaV3, TransactionResult, Uint256, VecM,
    WriteXdr,
};

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
// TODO: add ledger info and application order
pub struct GetTransactionResponseRaw {
    pub status: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

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

    #[serde(rename = "events", skip_serializing_if = "Option::is_none", default)]
    pub events: Option<GetTransactionEventsRaw>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Default)]
pub struct GetTransactionEventsRaw {
    #[serde(
        rename = "contractEventsXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub contract_events_xdr: Option<Vec<Vec<String>>>,

    #[serde(
        rename = "diagnosticEventsXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub diagnostic_events_xdr: Option<Vec<String>>,

    #[serde(
        rename = "transactionEventsXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub transaction_events_xdr: Option<Vec<String>>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct GetTransactionEvents {
    pub contract_events: Vec<Vec<ContractEvent>>,
    pub diagnostic_events: Vec<DiagnosticEvent>,
    pub transaction_events: Vec<TransactionEvent>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetTransactionResponse {
    pub status: String,
    pub ledger: Option<u32>,
    pub envelope: Option<xdr::TransactionEnvelope>,
    pub result: Option<xdr::TransactionResult>,
    pub result_meta: Option<xdr::TransactionMeta>,
    pub events: GetTransactionEvents,
}

impl TryInto<GetTransactionResponse> for GetTransactionResponseRaw {
    type Error = xdr::Error;

    fn try_into(self) -> Result<GetTransactionResponse, Self::Error> {
        let events = self.events.unwrap_or_default();
        let result_meta: Option<xdr::TransactionMeta> = self
            .result_meta_xdr
            .map(|v| ReadXdr::from_xdr_base64(v, Limits::none()))
            .transpose()?;

        let events = match result_meta {
            Some(xdr::TransactionMeta::V4(_)) => GetTransactionEvents {
                contract_events: events
                    .contract_events_xdr
                    .unwrap_or_default()
                    .into_iter()
                    .map(|es| {
                        es.into_iter()
                            .filter_map(|e| ContractEvent::from_xdr_base64(e, Limits::none()).ok())
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<Vec<ContractEvent>>>(),

                diagnostic_events: events
                    .diagnostic_events_xdr
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|e| DiagnosticEvent::from_xdr_base64(e, Limits::none()).ok())
                    .collect(),

                transaction_events: events
                    .transaction_events_xdr
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|e| TransactionEvent::from_xdr_base64(e, Limits::none()).ok())
                    .collect(),
            },

            Some(xdr::TransactionMeta::V3(TransactionMetaV3 {
                soroban_meta: Some(ref meta),
                ..
            })) => GetTransactionEvents {
                contract_events: vec![],
                transaction_events: vec![],
                diagnostic_events: meta.diagnostic_events.clone().into(),
            },

            _ => GetTransactionEvents {
                contract_events: vec![],
                transaction_events: vec![],
                diagnostic_events: vec![],
            },
        };

        Ok(GetTransactionResponse {
            status: self.status,
            ledger: self.ledger,
            envelope: self
                .envelope_xdr
                .map(|v| ReadXdr::from_xdr_base64(v, Limits::none()))
                .transpose()?,
            result: self
                .result_xdr
                .map(|v| ReadXdr::from_xdr_base64(v, Limits::none()))
                .transpose()?,
            result_meta,
            events,
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
        })) = &self.result_meta
        {
            return Ok(return_value.clone());
        }

        if let Some(xdr::TransactionMeta::V4(xdr::TransactionMetaV4 {
            soroban_meta:
                Some(xdr::SorobanTransactionMetaV2 {
                    return_value: Some(return_value),
                    ..
                }),
            ..
        })) = &self.result_meta
        {
            return Ok(return_value.clone());
        }

        Err(Error::MissingOp)
    }
}

#[serde_as]
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetTransactionsResponseRaw {
    pub transactions: Vec<GetTransactionResponseRaw>,
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
    pub transactions: Vec<GetTransactionResponse>,
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
pub struct GetHealthResponse {
    pub status: String,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "oldestLedger")]
    pub oldest_ledger: u32,
    #[serde(rename = "ledgerRetentionWindow")]
    pub ledger_retention_window: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetVersionInfoResponse {
    pub version: String,
    #[serde(rename = "commitHash")]
    pub commmit_hash: String,
    #[serde(rename = "buildTimestamp")]
    pub build_timestamp: String,
    #[serde(rename = "captiveCoreVersion")]
    pub captive_core_version: String,
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
pub struct GetFeeStatsResponse {
    #[serde(rename = "sorobanInclusionFee")]
    pub soroban_inclusion_fee: FeeStat,
    #[serde(rename = "inclusionFee")]
    pub inclusion_fee: FeeStat,
    #[serde(
        rename = "latestLedger",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct FeeStat {
    pub max: String,
    pub min: String,
    // Fee value which occurs the most often
    pub mode: String,
    // 10th nearest-rank fee percentile
    pub p10: String,
    // 20th nearest-rank fee percentile
    pub p20: String,
    // 30th nearest-rank fee percentile
    pub p30: String,
    // 40th nearest-rank fee percentile
    pub p40: String,
    // 50th nearest-rank fee percentile
    pub p50: String,
    // 60th nearest-rank fee percentile
    pub p60: String,
    // 70th nearest-rank fee percentile
    pub p70: String,
    // 80th nearest-rank fee percentile
    pub p80: String,
    // 90th nearest-rank fee percentile.
    pub p90: String,
    // 95th nearest-rank fee percentile.
    pub p95: String,
    // 99th nearest-rank fee percentile
    pub p99: String,
    // How many transactions are part of the distribution
    #[serde(
        rename = "transactionCount",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub transaction_count: u32,
    // How many consecutive ledgers form the distribution
    #[serde(
        rename = "ledgerCount",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub ledger_count: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default, Clone)]
pub struct Cost {
    #[serde(
        rename = "cpuInsns",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub cpu_insns: u64,
    #[serde(
        rename = "memBytes",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub mem_bytes: u64,
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
    #[serde(
        rename = "minResourceFee",
        deserialize_with = "deserialize_number_from_string",
        default
    )]
    pub min_resource_fee: u64,
    #[serde(default)]
    pub cost: Cost,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub results: Vec<SimulateHostFunctionResultRaw>,
    #[serde(rename = "transactionData", default)]
    pub transaction_data: String,
    #[serde(
        deserialize_with = "deserialize_default_from_null",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub events: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
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
                        .map(|a| {
                            Ok(SorobanAuthorizationEntry::from_xdr_base64(
                                a,
                                Limits::none(),
                            )?)
                        })
                        .collect::<Result<_, Error>>()?,
                    xdr: xdr::ScVal::from_xdr_base64(&r.xdr, Limits::none())?,
                })
            })
            .collect()
    }

    ///
    /// # Errors
    pub fn events(&self) -> Result<Vec<DiagnosticEvent>, Error> {
        self.events
            .iter()
            .map(|e| Ok(DiagnosticEvent::from_xdr_base64(e, Limits::none())?))
            .collect()
    }

    ///
    /// # Errors
    pub fn transaction_data(&self) -> Result<SorobanTransactionData, Error> {
        Ok(SorobanTransactionData::from_xdr_base64(
            &self.transaction_data,
            Limits::none(),
        )?)
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
pub struct GetEventsResponse {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub events: Vec<Event>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "latestLedgerCloseTime")]
    pub latest_ledger_close_time: String,
    #[serde(rename = "oldestLedger")]
    pub oldest_ledger: u32,
    #[serde(rename = "oldestLedgerCloseTime")]
    pub oldest_ledger_close_time: String,
    pub cursor: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetLedgersResponse {
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(
        rename = "latestLedgerCloseTime",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger_close_time: i64,
    #[serde(rename = "oldestLedger")]
    pub oldest_ledger: u32,
    #[serde(rename = "oldestLedgerCloseTime")]
    pub oldest_ledger_close_time: i64,
    pub cursor: String,
    pub ledgers: Vec<Ledger>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct Ledger {
    pub hash: String,
    pub sequence: u32,
    #[serde(rename = "ledgerCloseTime")]
    pub ledger_close_time: String,
    #[serde(rename = "headerXdr")]
    pub header_xdr: String,
    #[serde(rename = "headerJson")]
    pub header_json: Option<LedgerHeaderHistoryEntry>,
    #[serde(rename = "metadataXdr")]
    pub metadata_xdr: String,
    #[serde(rename = "metadataJson")]
    pub metadata_json: Option<LedgerCloseMeta>,
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
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: String,

    pub ledger: u32,
    #[serde(rename = "ledgerClosedAt")]
    pub ledger_closed_at: String,
    #[serde(rename = "contractId")]
    pub contract_id: String,

    pub id: String,

    #[serde(rename = "operationIndex")]
    pub operation_index: u32,
    #[serde(rename = "transactionIndex")]
    pub transaction_index: u32,
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    #[deprecated(note = "This field is deprecated by Stellar RPC")]
    #[serde(rename = "inSuccessfulContractCall")]
    pub is_successful_contract_call: bool,

    pub topic: Vec<String>,
    pub value: String,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Event {} [{}]:",
            self.id,
            self.event_type.to_ascii_uppercase()
        )?;
        writeln!(
            f,
            "  Ledger:   {} (closed at {})",
            self.ledger, self.ledger_closed_at
        )?;
        writeln!(f, "  Contract: {}", self.contract_id)?;
        writeln!(f, "  Topics:")?;

        for topic in &self.topic {
            let scval =
                xdr::ScVal::from_xdr_base64(topic, Limits::none()).map_err(|_| std::fmt::Error)?;
            writeln!(f, "            {scval:?}")?;
        }

        let scval = xdr::ScVal::from_xdr_base64(&self.value, Limits::none())
            .map_err(|_| std::fmt::Error)?;

        writeln!(f, "  Value:    {scval:?}")
    }
}

pub type SegmentFilter = String;
pub type TopicFilter = Vec<SegmentFilter>;

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
            let scval = xdr::ScVal::from_xdr_base64(topic, Limits::none())?;
            colored!(
                stdout,
                "            {}{:?}{}\n",
                fg!(Some(Color::Green)),
                scval,
                reset!(),
            )?;
        }

        let scval = xdr::ScVal::from_xdr_base64(&self.value, Limits::none())?;
        colored!(
            stdout,
            "  Value: {}{:?}{}\n\n",
            fg!(Some(Color::Green)),
            scval,
            reset!(),
        )?;

        Ok(())
    }
}

/// Defines non-root authorization for simulated transactions.
pub enum AuthMode {
    Enforce,
    Record,
    RecordAllowNonRoot,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, clap::ValueEnum)]
pub enum EventType {
    All,
    Contract,
    System,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum LedgerStart {
    Ledger(u32),
    Cursor(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EventStart {
    Ledger(u32),
    Cursor(String),
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct FullLedgerEntry {
    pub key: LedgerKey,
    pub val: LedgerEntryData,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger: u32,
    #[serde(
        rename = "liveUntilLedgerSeq",
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_option_number_from_string",
        default
    )]
    pub live_until_ledger_seq: Option<u32>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct FullLedgerEntries {
    pub entries: Vec<FullLedgerEntry>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: i64,
}

#[derive(Debug, Clone)]
pub struct Client {
    base_url: Arc<str>,
    timeout_in_secs: u64,
    http_client: Arc<HttpClient>,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
/// Contains configuration for how resources will be calculated when simulating transactions.
pub struct ResourceConfig {
    /// Allow this many extra instructions when budgeting resources.
    #[serde(rename = "instructionLeeway")]
    pub instruction_leeway: u64,
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
        let headers = Self::default_http_headers();
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

    /// Create a new client with a timeout in seconds
    /// # Errors
    #[deprecated(
        note = "To be marked private in a future major release. Please use `new_with_headers` instead."
    )]
    pub fn new_with_timeout(base_url: &str, timeout: u64) -> Result<Self, Error> {
        let mut client = Self::new(base_url)?;
        client.timeout_in_secs = timeout;
        Ok(client)
    }

    /// Create a new client with additional headers
    /// # Errors
    pub fn new_with_headers(base_url: &str, additional_headers: HeaderMap) -> Result<Self, Error> {
        let mut client = Self::new(base_url)?;
        let mut headers = Self::default_http_headers();

        for (key, value) in additional_headers {
            headers.insert(key.ok_or(Error::InvalidResponse)?, value);
        }

        let http_client = Arc::new(
            HttpClientBuilder::default()
                .set_headers(headers)
                .build(base_url)?,
        );

        client.http_client = http_client;
        Ok(client)
    }

    fn default_http_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Client-Name", unsafe {
            "rs-stellar-rpc-client".parse().unwrap_unchecked()
        });
        let version = VERSION.unwrap_or("devel");
        headers.insert("X-Client-Version", unsafe {
            version.parse().unwrap_unchecked()
        });

        headers
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn client(&self) -> &HttpClient {
        &self.http_client
    }

    ///
    /// # Errors
    pub async fn friendbot_url(&self) -> Result<String, Error> {
        let network = self.get_network().await?;
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
        Ok(self
            .client()
            .request("getNetwork", ObjectParams::new())
            .await?)
    }

    ///
    /// # Errors
    pub async fn get_health(&self) -> Result<GetHealthResponse, Error> {
        Ok(self
            .client()
            .request("getHealth", ObjectParams::new())
            .await?)
    }

    ///
    /// # Errors
    pub async fn get_latest_ledger(&self) -> Result<GetLatestLedgerResponse, Error> {
        Ok(self
            .client()
            .request("getLatestLedger", ObjectParams::new())
            .await?)
    }

    ///
    /// # Errors
    pub async fn get_ledgers(
        &self,
        start: LedgerStart,
        limit: Option<usize>,
        format: Option<String>,
    ) -> Result<GetLedgersResponse, Error> {
        let mut oparams = ObjectParams::new();

        let mut pagination = serde_json::Map::new();
        if let Some(limit) = limit {
            pagination.insert("limit".to_string(), limit.into());
        }

        match start {
            LedgerStart::Ledger(l) => oparams.insert("startLedger", l)?,
            LedgerStart::Cursor(c) => {
                pagination.insert("cursor".to_string(), c.into());
            }
        }

        oparams.insert("pagination", pagination)?;

        if let Some(f) = format {
            oparams.insert("xdrFormat", f)?;
        }

        Ok(self.client().request("getLedgers", oparams).await?)
    }

    ///
    /// # Errors
    pub async fn get_account(&self, address: &str) -> Result<AccountEntry, Error> {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(address)?.0,
            ))),
        });
        let keys = Vec::from([key]);
        let response = self.get_ledger_entries(&keys).await?;
        let entries = response.entries.unwrap_or_default();

        if entries.is_empty() {
            return Err(Error::NotFound("Account".to_string(), address.to_owned()));
        }

        let ledger_entry = &entries[0];
        let mut read = Limited::new(ledger_entry.xdr.as_bytes(), Limits::none());

        if let LedgerEntryData::Account(entry) = LedgerEntryData::read_xdr_base64(&mut read)? {
            Ok(entry)
        } else {
            Err(Error::InvalidResponse)
        }
    }

    /// Get network fee stats
    /// # Errors
    pub async fn get_fee_stats(&self) -> Result<GetFeeStatsResponse, Error> {
        Ok(self
            .client()
            .request("getFeeStats", ObjectParams::new())
            .await?)
    }

    ///
    /// # Errors
    pub async fn get_version_info(&self) -> Result<GetVersionInfoResponse, Error> {
        Ok(self
            .client()
            .request("getVersionInfo", ObjectParams::new())
            .await?)
    }

    /// Send a transaction to the network and get back the hash of the transaction.
    /// # Errors
    pub async fn send_transaction(&self, tx: &TransactionEnvelope) -> Result<Hash, Error> {
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
                .ok_or(Error::MissingError)
                .and_then(|x| {
                    TransactionResult::read_xdr_base64(&mut Limited::new(
                        x.as_bytes(),
                        Limits::none(),
                    ))
                    .map_err(|_| Error::InvalidResponse)
                })
                .map(|r| r.result)?;

            return Err(Error::TransactionSubmissionFailed(format!("{error:#?}")));
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
        auth_mode: Option<AuthMode>,
    ) -> Result<SimulateTransactionResponse, Error> {
        let base64_tx = tx.to_xdr_base64(Limits::none())?;
        let mut params = ObjectParams::new();

        params.insert("transaction", base64_tx)?;

        match auth_mode {
            Some(AuthMode::Enforce) => {
                params.insert("authMode", "enforce")?;
            }
            Some(AuthMode::Record) => {
                params.insert("authMode", "record")?;
            }
            Some(AuthMode::RecordAllowNonRoot) => {
                params.insert("authMode", "record_allow_nonroot")?;
            }
            None => {}
        }

        let sim_res = self.client().request("simulateTransaction", params).await?;

        Ok(sim_res)
    }

    /// Internal function, not to be used.
    /// # Errors
    pub async fn next_simulate_transaction_envelope(
        &self,
        tx: &TransactionEnvelope,
        auth_mode: Option<AuthMode>,
        resource_config: Option<ResourceConfig>,
    ) -> Result<SimulateTransactionResponse, Error> {
        let base64_tx = tx.to_xdr_base64(Limits::none())?;
        let mut params = ObjectParams::new();

        params.insert("transaction", base64_tx)?;

        match auth_mode {
            Some(AuthMode::Enforce) => {
                params.insert("authMode", "enforce")?;
            }
            Some(AuthMode::Record) => {
                params.insert("authMode", "record")?;
            }
            Some(AuthMode::RecordAllowNonRoot) => {
                params.insert("authMode", "record_allow_nonroot")?;
            }
            None => {}
        }

        if let Some(ref config) = resource_config {
            let mut resource_config_params = ObjectParams::new();
            resource_config_params.insert("instructionLeeway", config.instruction_leeway)?;
            params.insert("resourceConfig", resource_config)?;
        }

        let sim_res = self.client().request("simulateTransaction", params).await?;

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
            match response.status.as_str() {
                "SUCCESS" => return Ok(response),

                "FAILED" => {
                    return Err(Error::TransactionSubmissionFailed(format!(
                        "{:#?}",
                        response.result
                    )))
                }

                "NOT_FOUND" => (),
                _ => {
                    return Err(Error::UnexpectedTransactionStatus(response.status));
                }
            }

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
        let mut base64_keys: Vec<String> = vec![];

        for k in keys {
            let base64_result = k.to_xdr_base64(Limits::none());
            if base64_result.is_err() {
                return Err(Error::Xdr(XdrError::Invalid));
            }
            base64_keys.push(k.to_xdr_base64(Limits::none())?);
        }

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
        let GetLedgerEntriesResponse {
            entries,
            latest_ledger,
        } = self.get_ledger_entries(&keys).await?;
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
                        key: LedgerKey::from_xdr_base64(key, Limits::none())?,
                        val: LedgerEntryData::from_xdr_base64(xdr, Limits::none())?,
                        live_until_ledger_seq: *live_until_ledger_seq_ledger_seq,
                        last_modified_ledger: *last_modified_ledger,
                    })
                },
            )
            .collect::<Result<Vec<_>, Error>>()?;
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
        topics: &[TopicFilter],
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
        }
        oparams.insert("filters", vec![filters])?;
        oparams.insert("pagination", pagination)?;

        Ok(self.client().request("getEvents", oparams).await?)
    }

    ///
    /// # Errors
    pub async fn get_contract_data(
        &self,
        contract_id: &[u8; 32],
    ) -> Result<ContractDataEntry, Error> {
        // Get the contract from the network
        let contract_key = LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: xdr::ScAddress::Contract(ContractId(xdr::Hash(*contract_id))),
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
        match LedgerEntryData::from_xdr_base64(&contract_ref_entry.xdr, Limits::none())? {
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
        match LedgerEntryData::from_xdr_base64(&contract_data_entry.xdr, Limits::none())? {
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

    fn read_json_file(name: &str) -> String {
        let repo_root = get_repo_root();
        let fixture_path = repo_root.join("src").join("fixtures").join(name);
        fs::read_to_string(fixture_path).expect(&format!("Failed to read {name:?}"))
    }

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

    #[test]
    fn test_parse_transaction_response_p23() {
        let response_content = read_json_file("transaction_response_p23.json");
        let full_response: serde_json::Value = serde_json::from_str(&response_content)
            .expect("Failed to parse JSON from transaction_response_p23.json");
        let result = full_response["result"].clone();
        let raw_response: GetTransactionResponseRaw = serde_json::from_value(result)
            .expect("Failed to parse 'result' into GetTransactionResponseRaw");
        let response: GetTransactionResponse = raw_response
            .try_into()
            .expect("Failed to convert GetTransactionsResponseRaw to GetTransactionsResponse");

        assert_eq!(2, response.events.transaction_events.iter().len());
        assert_eq!(1, response.events.contract_events.len());
        assert_eq!(21, response.events.diagnostic_events.iter().len());
    }

    #[test]
    fn test_parse_transaction_response_p22() {
        let response_content = read_json_file("transaction_response_p22.json");
        let full_response: serde_json::Value = serde_json::from_str(&response_content)
            .expect("Failed to parse JSON from transaction_response_p22.json");
        let result = full_response["result"].clone();
        let raw_response: GetTransactionResponseRaw = serde_json::from_value(result)
            .expect("Failed to parse 'result' into GetTransactionResponseRaw");
        let response: GetTransactionResponse = raw_response
            .try_into()
            .expect("Failed to convert GetTransactionsResponseRaw to GetTransactionsResponse");

        assert_eq!(23, response.events.diagnostic_events.iter().len());
    }

    #[test]
    fn test_parse_get_transactions_response() {
        let response_content = read_json_file("transactions_response.json");

        // Parse the entire response
        let full_response: serde_json::Value = serde_json::from_str(&response_content)
            .expect("Failed to parse JSON from transactions_response.json");

        // Extract the "result" field
        let result = full_response["result"].clone();
        // Parse the "result" content as GetTransactionsResponseRaw
        let raw_response: GetTransactionsResponseRaw = serde_json::from_value(result)
            .expect("Failed to parse 'result' into GetTransactionsResponseRaw");

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
        //assert_eq!(response.transactions[0].application_order, 1);
        //assert_eq!(response.transactions[0].ledger, 554000);
    }

    #[test]
    fn test_rpc_url_default_ports() {
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
    fn test_parse_events_response() {
        let response_content = read_json_file("events_response_p23.json");
        let full_response: serde_json::Value = serde_json::from_str(&response_content)
            .expect("Failed to parse JSON from events_response_p23.json");
        let result = full_response["result"].clone();

        // Deserialize
        let resp: GetEventsResponse = serde_json::from_value(result.clone())
            .expect("Failed to parse 'result' into GetEventsResponse");

        // Re-serialize
        let reserialized = serde_json::to_value(&resp)
            .expect("Failed to serialize response");

        // Compare
        assert_eq!(result, reserialized, "Deserialization should preserve all data");
    }

    #[test]
    // Taken from [RPC server
    // tests](https://github.com/stellar/soroban-tools/blob/main/cmd/soroban-rpc/internal/methods/get_events_test.go#L21).
    fn test_does_topic_match() {
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
