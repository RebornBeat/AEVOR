//! Move compiler with AEVOR extensions.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompileOptions {
    pub optimize: bool,
    pub verify_privacy: bool,
    pub tee_compatible: bool,
    pub target_version: u32,
}
impl Default for CompileOptions {
    fn default() -> Self { Self { optimize: true, verify_privacy: true, tee_compatible: true, target_version: 1 } }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParsedModule { pub name: String, pub source: String, pub ast: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TypeCheckedModule { pub parsed: ParsedModule, pub type_info: Vec<u8> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedModule {
    pub type_checked: TypeCheckedModule,
    pub bytecode: Vec<u8>,
    pub privacy_verified: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompileUnit { pub source: String, pub module_name: String }

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
#[error("compile error in {module}: {message}")]
pub struct CompileError { pub module: String, pub message: String }

pub struct MoveCompiler { options: CompileOptions }
impl MoveCompiler {
    pub fn new(options: CompileOptions) -> Self { Self { options } }
    pub fn parse(&self, unit: &CompileUnit) -> crate::MoveResult<ParsedModule> {
        Ok(ParsedModule { name: unit.module_name.clone(), source: unit.source.clone(), ast: Vec::new() })
    }
    pub fn type_check(&self, parsed: ParsedModule) -> crate::MoveResult<TypeCheckedModule> {
        Ok(TypeCheckedModule { parsed, type_info: Vec::new() })
    }
    pub fn verify(&self, tc: TypeCheckedModule) -> crate::MoveResult<VerifiedModule> {
        Ok(VerifiedModule { type_checked: tc, bytecode: Vec::new(), privacy_verified: self.options.verify_privacy })
    }
}
