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
