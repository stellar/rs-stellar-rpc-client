use serde_json;
use stellar_xdr::curr::{DiagnosticEvent, Limits, ReadXdr};

pub fn diagnostic_events(events: &[String], level: tracing::Level) {
    for (i, event_xdr) in events.iter().enumerate() {
        let event_result = DiagnosticEvent::from_xdr_base64(event_xdr, Limits::none());
        let json_result = event_result
            .as_ref()
            .ok()
            .and_then(|event| serde_json::to_string(event).ok());

        let log_message = match (event_result, json_result) {
            (Ok(_), Some(json)) => format!("{i}: {event_xdr:#?} {json}"),
            (Err(e), _) => format!("{i}: {event_xdr:#?} Failed to decode DiagnosticEvent XDR: {e}"),
            (Ok(_), None) => format!("{i}: {event_xdr:#?} JSON encoding of DiagnosticEvent failed"),
        };

        match level {
            tracing::Level::TRACE => tracing::trace!("{}", log_message),
            tracing::Level::INFO => tracing::info!("{}", log_message),
            tracing::Level::ERROR => tracing::error!("{}", log_message),
            _ => tracing::debug!("{}", log_message), // Default to debug for other levels
        }
    }
}
