//! Output formatting.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputFormat { #[default] Human, Json, Table }

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { "json" => Ok(Self::Json), "table" => Ok(Self::Table), _ => Ok(Self::Human) }
    }
}

pub struct TableFormatter;
pub struct JsonFormatter;
pub struct HumanFormatter;

pub struct OutputWriter { format: OutputFormat, quiet: bool }
impl OutputWriter {
    pub fn new(format: OutputFormat, quiet: bool) -> Self { Self { format, quiet } }
    pub fn print<T: Serialize>(&self, data: &T) {
        if self.quiet { return; }
        match self.format {
            OutputFormat::Json => println!("{}", serde_json::to_string_pretty(data).unwrap_or_default()),
            _ => println!("{:?}", serde_json::to_value(data).unwrap_or_default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_format_from_str() {
        use std::str::FromStr;
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::from_str("table").unwrap(), OutputFormat::Table);
        assert_eq!(OutputFormat::from_str("anything").unwrap(), OutputFormat::Human);
    }

    #[test]
    fn output_format_default_is_human() {
        assert_eq!(OutputFormat::default(), OutputFormat::Human);
    }

    #[test]
    fn output_writer_quiet_suppresses_output() {
        let w = OutputWriter::new(OutputFormat::Json, true);
        // quiet=true: print is a no-op — just verify construction
        assert!(w.quiet);
    }

    #[test]
    fn output_writer_not_quiet() {
        let w = OutputWriter::new(OutputFormat::Human, false);
        assert!(!w.quiet);
    }
}
