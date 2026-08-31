//! Conversions between JSON, YAML, TOML and CSV.

use anyhow::{Context, Result};

use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Convert;

static P_INDENT: &[Param] = &[Param::valued(
    "indent",
    Some('i'),
    "N",
    "2",
    "Spaces of indentation",
)];
static P_CSV_IN: &[Param] = &[
    Param::valued(
        "delimiter",
        Some('d'),
        "CHAR",
        ",",
        "Field separator in the input",
    ),
    Param::flag(
        "no-header",
        None,
        "Treat the first row as data, not as column names",
    ),
    Param::valued(
        "indent",
        Some('i'),
        "N",
        "2",
        "Spaces of indentation, 0 for one line",
    ),
];
static P_CSV_OUT: &[Param] = &[Param::valued(
    "delimiter",
    Some('d'),
    "CHAR",
    ",",
    "Field separator in the output",
)];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "json-format",
            CAT,
            Feed::Buffer,
            "Pretty print JSON",
            |s, p| {
                let value = parse_json(s)?;
                let indent: usize = p.parse("indent")?;
                let pad = vec![b' '; indent];
                let mut buffer = Vec::new();
                let formatter = serde_json::ser::PrettyFormatter::with_indent(&pad);
                let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
                serde::Serialize::serialize(&value, &mut serializer)?;
                Ok(String::from_utf8(buffer)?)
            },
        )
        .aliases(&["json-pretty", "json-beautify"])
        .params(P_INDENT)
        .examples(&[
            "txc json-format --file data.json",
            "echo '{\"a\":1}' | txc json-format",
        ]),
    );

    out.push(
        Op::new(
            "json-minify",
            CAT,
            Feed::Buffer,
            "Remove all whitespace from JSON",
            |s, _| Ok(serde_json::to_string(&parse_json(s)?)?),
        )
        .aliases(&["json-compact"]),
    );

    out.push(
        Op::new(
            "json-to-yaml",
            CAT,
            Feed::Buffer,
            "Convert JSON to YAML",
            |s, _| Ok(serde_yaml_ng::to_string(&parse_json(s)?)?),
        )
        .aliases(&["json2yaml"])
        .examples(&["txc json-to-yaml --file config.json"]),
    );

    out.push(
        Op::new(
            "yaml-to-json",
            CAT,
            Feed::Buffer,
            "Convert YAML to JSON",
            |s, p| {
                let value: serde_json::Value = parse_yaml(s)?;
                render_json(&value, p)
            },
        )
        .aliases(&["yaml2json"])
        .params(P_INDENT),
    );

    out.push(
        Op::new(
            "json-to-toml",
            CAT,
            Feed::Buffer,
            "Convert JSON to TOML",
            |s, _| {
                let value: toml::Value =
                    serde_json::from_str(s).context("input is not valid JSON")?;
                toml::to_string_pretty(&value).context("this JSON has no TOML equivalent")
            },
        )
        .aliases(&["json2toml"]),
    );

    out.push(
        Op::new(
            "toml-to-json",
            CAT,
            Feed::Buffer,
            "Convert TOML to JSON",
            |s, p| {
                let value: serde_json::Value =
                    toml::from_str(s).context("input is not valid TOML")?;
                render_json(&value, p)
            },
        )
        .aliases(&["toml2json"])
        .params(P_INDENT)
        .examples(&["txc toml-to-json --file Cargo.toml"]),
    );

    out.push(
        Op::new(
            "yaml-to-toml",
            CAT,
            Feed::Buffer,
            "Convert YAML to TOML",
            |s, _| {
                let value: toml::Value = parse_yaml(s)?;
                toml::to_string_pretty(&value).context("this YAML has no TOML equivalent")
            },
        )
        .aliases(&["yaml2toml"]),
    );

    out.push(
        Op::new(
            "toml-to-yaml",
            CAT,
            Feed::Buffer,
            "Convert TOML to YAML",
            |s, _| {
                let value: serde_yaml_ng::Value =
                    toml::from_str(s).context("input is not valid TOML")?;
                Ok(serde_yaml_ng::to_string(&value)?)
            },
        )
        .aliases(&["toml2yaml"]),
    );

    out.push(
        Op::new(
            "csv-to-json",
            CAT,
            Feed::Buffer,
            "Convert CSV rows to JSON",
            |s, p| {
                let delimiter = delimiter_of(p)?;
                let has_header = !p.flag("no-header");
                let mut reader = csv::ReaderBuilder::new()
                    .delimiter(delimiter)
                    .has_headers(has_header)
                    .from_reader(s.as_bytes());

                let value = if has_header {
                    let headers = reader
                        .headers()
                        .context("cannot read the header row")?
                        .clone();
                    let mut rows = Vec::new();
                    for record in reader.records() {
                        let record = record.context("cannot read a CSV row")?;
                        let object: serde_json::Map<String, serde_json::Value> = headers
                            .iter()
                            .zip(record.iter())
                            .map(|(key, field)| (key.to_string(), guess_type(field)))
                            .collect();
                        rows.push(serde_json::Value::Object(object));
                    }
                    serde_json::Value::Array(rows)
                } else {
                    let mut rows = Vec::new();
                    for record in reader.records() {
                        let record = record.context("cannot read a CSV row")?;
                        rows.push(serde_json::Value::Array(
                            record.iter().map(guess_type).collect(),
                        ));
                    }
                    serde_json::Value::Array(rows)
                };

                render_json(&value, p)
            },
        )
        .aliases(&["csv2json"])
        .params(P_CSV_IN)
        .examples(&["txc csv-to-json --file people.csv"]),
    );

    out.push(
        Op::new(
            "json-to-csv",
            CAT,
            Feed::Buffer,
            "Convert an array of JSON objects to CSV",
            |s, p| {
                let value = parse_json(s)?;
                let rows = value
                    .as_array()
                    .context("expected a JSON array of objects at the top level")?;

                // The column order follows the first appearance of each key.
                let mut columns: Vec<String> = Vec::new();
                for row in rows {
                    if let Some(object) = row.as_object() {
                        for key in object.keys() {
                            if !columns.iter().any(|c| c == key) {
                                columns.push(key.clone());
                            }
                        }
                    }
                }

                let mut writer = csv::WriterBuilder::new()
                    .delimiter(delimiter_of(p)?)
                    .from_writer(Vec::new());
                writer.write_record(&columns)?;
                for row in rows {
                    let object = row.as_object().context("every element must be an object")?;
                    let fields: Vec<String> = columns
                        .iter()
                        .map(|column| match object.get(column) {
                            Some(serde_json::Value::String(text)) => text.clone(),
                            Some(serde_json::Value::Null) | None => String::new(),
                            Some(other) => other.to_string(),
                        })
                        .collect();
                    writer.write_record(&fields)?;
                }
                Ok(String::from_utf8(writer.into_inner()?)?
                    .trim_end()
                    .to_string())
            },
        )
        .aliases(&["json2csv"])
        .params(P_CSV_OUT),
    );

    out.push(
        Op::new(
            "csv-to-markdown",
            CAT,
            Feed::Buffer,
            "Render CSV as a Markdown table",
            |s, p| {
                let mut reader = csv::ReaderBuilder::new()
                    .delimiter(delimiter_of(p)?)
                    .has_headers(false)
                    .from_reader(s.as_bytes());

                let rows: Vec<Vec<String>> = reader
                    .records()
                    .map(|record| {
                        record
                            .map(|r| r.iter().map(str::to_string).collect())
                            .context("cannot read a CSV row")
                    })
                    .collect::<Result<_>>()?;
                anyhow::ensure!(!rows.is_empty(), "there are no rows to render");

                let width = rows.iter().map(Vec::len).max().unwrap_or(0);
                let mut table = Vec::new();
                table.push(format!("| {} |", pad_row(&rows[0], width).join(" | ")));
                table.push(format!("| {} |", vec!["---"; width].join(" | ")));
                for row in &rows[1..] {
                    table.push(format!("| {} |", pad_row(row, width).join(" | ")));
                }
                Ok(table.join("\n"))
            },
        )
        .aliases(&["csv2md"])
        .params(P_CSV_OUT)
        .examples(&["txc csv-to-markdown --file table.csv"]),
    );
}

fn parse_json(text: &str) -> Result<serde_json::Value> {
    serde_json::from_str(text).context("input is not valid JSON")
}

fn parse_yaml<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
    serde_yaml_ng::from_str(text).context("input is not valid YAML")
}

fn render_json(value: &serde_json::Value, p: &crate::params::Params) -> Result<String> {
    let indent: usize = p.parse("indent").unwrap_or(2);
    if indent == 0 {
        return Ok(serde_json::to_string(value)?);
    }
    let pad = vec![b' '; indent];
    let mut buffer = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(&pad);
    let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
    serde::Serialize::serialize(value, &mut serializer)?;
    Ok(String::from_utf8(buffer)?)
}

fn delimiter_of(p: &crate::params::Params) -> Result<u8> {
    let text = p.get("delimiter");
    let ch = match text {
        "\\t" | "tab" => '\t',
        other => other
            .chars()
            .next()
            .context("--delimiter cannot be empty")?,
    };
    u8::try_from(ch as u32).context("--delimiter must be a single byte character")
}

/// CSV has no types, so numbers and booleans are recognised by shape.
fn guess_type(field: &str) -> serde_json::Value {
    let trimmed = field.trim();
    if trimmed.is_empty() {
        return serde_json::Value::Null;
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return serde_json::Value::from(value);
    }
    if let Ok(value) = trimmed.parse::<f64>() {
        if trimmed.contains(['.', 'e', 'E']) {
            return serde_json::Value::from(value);
        }
    }
    match trimmed {
        "true" => serde_json::Value::Bool(true),
        "false" => serde_json::Value::Bool(false),
        other => serde_json::Value::String(other.to_string()),
    }
}

fn pad_row(row: &[String], width: usize) -> Vec<String> {
    let mut cells: Vec<String> = row.iter().map(|c| c.replace('|', "\\|")).collect();
    cells.resize(width, String::new());
    cells
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

    fn run(name: &str, input: &str) -> String {
        run_with(name, input, "")
    }

    #[test]
    fn formats_and_minifies_json() {
        assert_eq!(run("json-format", "{\"a\":1}"), "{\n  \"a\": 1\n}");
        assert_eq!(
            run_with("json-format", "{\"a\":1}", "indent=4"),
            "{\n    \"a\": 1\n}"
        );
        assert_eq!(run("json-minify", "{ \"a\" : 1 }"), "{\"a\":1}");
    }

    #[test]
    fn json_errors_name_the_format() {
        let op = find("json-format").unwrap();
        let error = op
            .apply("not json", &Params::for_op(op), None)
            .expect_err("invalid")
            .to_string();
        assert!(error.contains("not valid JSON"), "{error}");
    }

    #[test]
    fn keeps_key_order_through_a_round_trip() {
        let json = "{\"b\":1,\"a\":2}";
        assert_eq!(run("json-minify", json), json);
        let yaml = run("json-to-yaml", json);
        assert!(yaml.starts_with("b: 1"), "{yaml}");
    }

    #[test]
    fn converts_between_configuration_formats() {
        let json = "{\"name\":\"txc\",\"count\":2}";
        let yaml = run("json-to-yaml", json);
        assert_eq!(
            run("yaml-to-json", &yaml),
            "{\n  \"name\": \"txc\",\n  \"count\": 2\n}"
        );

        let toml_text = run("json-to-toml", json);
        assert!(toml_text.contains("name = \"txc\""), "{toml_text}");
        assert_eq!(
            run("toml-to-json", &toml_text),
            "{\n  \"name\": \"txc\",\n  \"count\": 2\n}"
        );

        assert!(run("toml-to-yaml", &toml_text).contains("name: txc"));
        assert!(run("yaml-to-toml", &yaml).contains("name = \"txc\""));
    }

    #[test]
    fn csv_becomes_json_with_guessed_types() {
        let csv = "name,age,member\nada,36,true\ngrace,45,false";
        assert_eq!(
            run_with("csv-to-json", csv, "indent=0"),
            "[{\"name\":\"ada\",\"age\":36,\"member\":true},{\"name\":\"grace\",\"age\":45,\"member\":false}]"
        );
    }

    #[test]
    fn csv_without_a_header_becomes_arrays() {
        assert_eq!(
            run_with("csv-to-json", "a,1\nb,2", "no-header indent=0"),
            "[[\"a\",1],[\"b\",2]]"
        );
    }

    #[test]
    fn json_becomes_csv_in_first_seen_column_order() {
        let json = "[{\"b\":1,\"a\":\"x\"},{\"a\":\"y\",\"b\":2}]";
        assert_eq!(run("json-to-csv", json), "b,a\n1,x\n2,y");
    }

    #[test]
    fn json_to_csv_needs_an_array() {
        let op = find("json-to-csv").unwrap();
        let error = op
            .apply("{\"a\":1}", &Params::for_op(op), None)
            .expect_err("not an array")
            .to_string();
        assert!(error.contains("array"), "{error}");
    }

    #[test]
    fn csv_becomes_a_markdown_table() {
        assert_eq!(
            run("csv-to-markdown", "name,age\nada,36"),
            "| name | age |\n| --- | --- |\n| ada | 36 |"
        );
    }

    #[test]
    fn tab_separated_input_is_accepted() {
        assert_eq!(
            run_with("csv-to-json", "a\tb\n1\t2", "delimiter=tab indent=0"),
            "[{\"a\":1,\"b\":2}]"
        );
    }
}
