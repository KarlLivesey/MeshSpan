// SPDX-License-Identifier: GPL-2.0-only

//! Typed HTTP retry guidance, separated from clocks and durable scheduling policy.

use std::time::UNIX_EPOCH;

use meshspan_domain::UnixMicros;

use crate::AcmeProtocolError;

/// A validated HTTP `Retry-After` value. The scheduler supplies receipt time for relative delays.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeRetryAfter {
    /// Non-negative relative delay in microseconds, bounded by the metadata time representation.
    DelayMicros(u64),
    /// Absolute HTTP date expressed on the Unix timeline.
    At(UnixMicros),
}

impl AcmeRetryAfter {
    /// Resolves this hint against authority-aligned response receipt time, not request start.
    ///
    /// Zero/past hints do not override local backoff. Unrepresentably distant deadlines saturate
    /// at the final metadata instant rather than silently allowing an earlier request.
    #[must_use]
    pub fn not_before(self, received_at: UnixMicros) -> Option<UnixMicros> {
        let candidate = match self {
            Self::DelayMicros(delay) => {
                let delay = i64::try_from(delay).unwrap_or(i64::MAX);
                UnixMicros::new(received_at.get().saturating_add(delay))
            }
            Self::At(instant) => instant,
        };
        (candidate > received_at).then_some(candidate)
    }

    pub(crate) fn parse(value: &str) -> Result<Self, AcmeProtocolError> {
        let value = value.trim_matches([' ', '\t']);
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            let seconds = value
                .parse::<u64>()
                .map_err(|_| AcmeProtocolError::InvalidResponse)?;
            let micros = seconds
                .checked_mul(1_000_000)
                .filter(|micros| i64::try_from(*micros).is_ok())
                .ok_or(AcmeProtocolError::InvalidResponse)?;
            return Ok(Self::DelayMicros(micros));
        }
        let instant =
            httpdate::parse_http_date(value).map_err(|_| AcmeProtocolError::InvalidResponse)?;
        let micros = instant
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AcmeProtocolError::InvalidResponse)?
            .as_micros();
        let micros = i64::try_from(micros).map_err(|_| AcmeProtocolError::InvalidResponse)?;
        Ok(Self::At(UnixMicros::new(micros)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AcmeResponseHeaders;

    #[test]
    fn seconds_and_all_http_date_forms_have_exact_deadlines() -> Result<(), AcmeProtocolError> {
        let received = UnixMicros::new(10_250_000);
        for value in ["120", "000120", " \t120\t "] {
            assert_eq!(
                AcmeRetryAfter::parse(value)?.not_before(received),
                Some(UnixMicros::new(130_250_000))
            );
        }
        for value in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(
                AcmeRetryAfter::parse(value)?.not_before(received),
                Some(UnixMicros::new(784_111_777_000_000))
            );
        }
        assert_eq!(AcmeRetryAfter::parse("0")?.not_before(received), None);
        assert_eq!(
            AcmeRetryAfter::At(UnixMicros::new(1)).not_before(received),
            None
        );
        assert_eq!(
            AcmeRetryAfter::DelayMicros(10).not_before(UnixMicros::new(i64::MAX - 1)),
            Some(UnixMicros::new(i64::MAX))
        );
        Ok(())
    }

    #[test]
    fn ambiguous_and_invalid_hints_fail_closed() -> Result<(), AcmeProtocolError> {
        for value in [
            "",
            " ",
            "+120",
            "-1",
            "1.5",
            "120, 240",
            "18446744073709551616",
            "9223372036855",
            "Sun, 31 Feb 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 UTC",
        ] {
            assert!(AcmeRetryAfter::parse(value).is_err(), "accepted {value:?}");
        }
        let headers = AcmeResponseHeaders::new(vec![
            ("retry-after".to_owned(), "120".to_owned()),
            ("retry-after".to_owned(), "120".to_owned()),
        ])?;
        assert!(headers.retry_after().is_err());
        assert_eq!(AcmeResponseHeaders::default().retry_after()?, None);
        Ok(())
    }
}
