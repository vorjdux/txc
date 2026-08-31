//! Timestamps and date formatting.

use anyhow::Context;
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};

use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Time;

/// The default output shape, chosen because it sorts and parses everywhere.
const DEFAULT_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

static P_NOW: &[Param] = &[
    Param::valued(
        "format",
        Some('t'),
        "FORMAT",
        DEFAULT_FORMAT,
        "strftime style format",
    ),
    Param::flag("utc", Some('u'), "Use UTC instead of the local time zone"),
    Param::flag("iso", None, "Use the RFC 3339 format"),
];
static P_FROM_TS: &[Param] = &[
    Param::valued(
        "format",
        Some('t'),
        "FORMAT",
        DEFAULT_FORMAT,
        "strftime style format",
    ),
    Param::flag(
        "utc",
        Some('u'),
        "Render in UTC instead of the local time zone",
    ),
    Param::flag("millis", Some('m'), "Read the input as milliseconds"),
    Param::flag("iso", None, "Use the RFC 3339 format"),
];
static P_MILLIS: &[Param] = &[Param::flag(
    "millis",
    Some('m'),
    "Print milliseconds instead of seconds",
)];
static P_TO_TS: &[Param] = &[
    Param::valued(
        "format",
        Some('t'),
        "FORMAT",
        DEFAULT_FORMAT,
        "strftime style format of the input",
    ),
    Param::flag(
        "utc",
        Some('u'),
        "Read the input as UTC instead of local time",
    ),
    Param::flag("millis", Some('m'), "Print milliseconds instead of seconds"),
];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "now",
            CAT,
            Feed::None,
            "Print the current date and time",
            |_, p| {
                let now = Utc::now();
                Ok(if p.flag("utc") {
                    render(now, p)
                } else {
                    render(now.with_timezone(&Local), p)
                })
            },
        )
        .aliases(&["date"])
        .params(P_NOW)
        .examples(&[
            "txc now",
            "txc now --utc --iso",
            "txc now --format '%A %d %B %Y'",
        ]),
    );

    out.push(
        Op::new(
            "timestamp",
            CAT,
            Feed::None,
            "Print the current Unix timestamp",
            |_, p| {
                let now = Utc::now();
                Ok(if p.flag("millis") {
                    now.timestamp_millis().to_string()
                } else {
                    now.timestamp().to_string()
                })
            },
        )
        .aliases(&["epoch", "unix"])
        .params(P_MILLIS)
        .examples(&["txc timestamp", "txc timestamp --millis"]),
    );

    out.push(
        Op::new(
            "from-timestamp",
            CAT,
            Feed::Lines,
            "Turn a Unix timestamp into a readable date",
            |s, p| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let value: i64 = trimmed
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{trimmed:?} is not a Unix timestamp"))?;

                let moment = if p.flag("millis") {
                    DateTime::from_timestamp_millis(value)
                } else {
                    DateTime::from_timestamp(value, 0)
                }
                .with_context(|| format!("{value} is outside the range of representable dates"))?;

                Ok(if p.flag("utc") {
                    render(moment, p)
                } else {
                    render(moment.with_timezone(&Local), p)
                })
            },
        )
        .aliases(&["ts2date", "unix-to-date"])
        .params(P_FROM_TS)
        .examples(&[
            "txc from-timestamp 1700000000",
            "txc from-timestamp --utc --iso 1700000000",
        ]),
    );

    out.push(
        Op::new(
            "to-timestamp",
            CAT,
            Feed::Lines,
            "Turn a date into a Unix timestamp",
            |s, p| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let format = p.get("format");

                // Accept a full date and time, a bare date, or RFC 3339.
                let naive = NaiveDateTime::parse_from_str(trimmed, format)
                    .or_else(|_| {
                        NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
                            .map(|d| d.and_hms_opt(0, 0, 0).expect("midnight is valid"))
                    })
                    .or_else(|_| DateTime::parse_from_rfc3339(trimmed).map(|d| d.naive_utc()))
                    .with_context(|| format!("{trimmed:?} does not match the format {format:?}"))?;

                let moment = if p.flag("utc") {
                    Utc.from_utc_datetime(&naive)
                } else {
                    Local
                        .from_local_datetime(&naive)
                        .single()
                        .context("that local time is ambiguous or does not exist")?
                        .with_timezone(&Utc)
                };

                Ok(if p.flag("millis") {
                    moment.timestamp_millis().to_string()
                } else {
                    moment.timestamp().to_string()
                })
            },
        )
        .aliases(&["date2ts", "date-to-unix"])
        .params(P_TO_TS)
        .examples(&[
            "txc to-timestamp --utc \"2023-11-14 22:13:20\"",
            "txc to-timestamp 2024-01-01",
        ]),
    );
}

fn render<Tz: TimeZone>(moment: DateTime<Tz>, p: &crate::params::Params) -> String
where
    Tz::Offset: std::fmt::Display,
{
    if p.flag("iso") {
        moment.to_rfc3339()
    } else {
        moment.format(p.get("format")).to_string()
    }
}

#[cfg(test)]
mod tests {
    use crate::params::Params;
    use crate::registry::find;

    fn run_with(name: &str, input: &str, options: &str) -> String {
        let op = find(name).expect("operation is registered");
        let params = Params::parse_kv(op, options).expect("options parse");
        op.apply(input, &params, None).expect("runs")
    }

    #[test]
    fn renders_a_known_timestamp_in_utc() {
        assert_eq!(
            run_with("from-timestamp", "1700000000", "utc"),
            "2023-11-14 22:13:20"
        );
        assert_eq!(
            run_with("from-timestamp", "1700000000", "utc format='%Y/%m/%d'"),
            "2023/11/14"
        );
        assert!(
            run_with("from-timestamp", "1700000000", "utc iso").starts_with("2023-11-14T22:13:20")
        );
    }

    #[test]
    fn reads_milliseconds_when_asked() {
        assert_eq!(
            run_with("from-timestamp", "1700000000000", "utc millis"),
            "2023-11-14 22:13:20"
        );
    }

    #[test]
    fn dates_round_trip_through_timestamps() {
        let stamp = run_with("to-timestamp", "2023-11-14 22:13:20", "utc");
        assert_eq!(stamp, "1700000000");
        assert_eq!(
            run_with("from-timestamp", &stamp, "utc"),
            "2023-11-14 22:13:20"
        );
    }

    #[test]
    fn accepts_a_bare_date_and_rfc3339() {
        assert_eq!(run_with("to-timestamp", "2024-01-01", "utc"), "1704067200");
        assert_eq!(
            run_with("to-timestamp", "2023-11-14T22:13:20+00:00", "utc"),
            "1700000000"
        );
    }

    #[test]
    fn reports_input_that_does_not_match_the_format() {
        let op = find("to-timestamp").unwrap();
        let error = op
            .apply("not a date", &Params::for_op(op), None)
            .expect_err("bad date")
            .to_string();
        assert!(error.contains("does not match the format"), "{error}");
    }

    #[test]
    fn timestamp_and_now_produce_something_sensible() {
        let op = find("timestamp").unwrap();
        let seconds: i64 = op
            .apply("", &Params::for_op(op), None)
            .unwrap()
            .parse()
            .expect("a number");
        // Any run of this test happens well after 2020 and well before 2100.
        assert!((1_577_836_800..4_102_444_800).contains(&seconds));

        let op = find("now").unwrap();
        assert_eq!(op.apply("", &Params::for_op(op), None).unwrap().len(), 19);
    }
}
