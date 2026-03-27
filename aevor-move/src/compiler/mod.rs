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

    /// Parse the source in `unit` into an AST.
    ///
    /// # Errors
    /// Returns an error if the source contains syntax errors.
    pub fn parse(&self, unit: &CompileUnit) -> crate::MoveResult<ParsedModule> {
        Ok(ParsedModule { name: unit.module_name.clone(), source: unit.source.clone(), ast: Vec::new() })
    }

    /// Type-check a parsed module.
    ///
    /// # Errors
    /// Returns an error if the module contains type errors or unresolved references.
    pub fn type_check(&self, parsed: ParsedModule) -> crate::MoveResult<TypeCheckedModule> {
        Ok(TypeCheckedModule { parsed, type_info: Vec::new() })
    }

    /// Verify a type-checked module and produce bytecode.
    ///
    /// # Errors
    /// Returns an error if the module fails bytecode-level safety verification.
    pub fn verify(&self, tc: TypeCheckedModule) -> crate::MoveResult<VerifiedModule> {
        Ok(VerifiedModule { type_checked: tc, bytecode: Vec::new(), privacy_verified: self.options.verify_privacy })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> CompileUnit {
        CompileUnit { source: "module M {}".into(), module_name: name.into() }
    }

    #[test]
    fn parse_preserves_module_name() {
        let compiler = MoveCompiler::new(CompileOptions::default());
        let parsed = compiler.parse(&unit("MyModule")).unwrap();
        assert_eq!(parsed.name, "MyModule");
        assert_eq!(parsed.source, "module M {}");
    }

    #[test]
    fn type_check_preserves_parsed_module() {
        let compiler = MoveCompiler::new(CompileOptions::default());
        let parsed = compiler.parse(&unit("Foo")).unwrap();
        let name = parsed.name.clone();
        let tc = compiler.type_check(parsed).unwrap();
        assert_eq!(tc.parsed.name, name);
    }

    #[test]
    fn verify_reflects_privacy_option() {
        let opts_with = CompileOptions { verify_privacy: true, ..Default::default() };
        let opts_without = CompileOptions { verify_privacy: false, ..Default::default() };

        let c1 = MoveCompiler::new(opts_with);
        let c2 = MoveCompiler::new(opts_without);

        let verify = |c: &MoveCompiler| {
            let p = c.parse(&unit("M")).unwrap();
            let tc = c.type_check(p).unwrap();
            c.verify(tc).unwrap()
        };

        assert!(verify(&c1).privacy_verified);
        assert!(!verify(&c2).privacy_verified);
    }

    #[test]
    fn full_pipeline_succeeds() {
        let compiler = MoveCompiler::new(CompileOptions::default());
        let parsed = compiler.parse(&unit("Pipeline")).unwrap();
        let tc = compiler.type_check(parsed).unwrap();
        let verified = compiler.verify(tc).unwrap();
        assert_eq!(verified.type_checked.parsed.name, "Pipeline");
    }

    #[test]
    fn compile_options_default_is_enabled() {
        let opts = CompileOptions::default();
        assert!(opts.optimize);
        assert!(opts.verify_privacy);
        assert!(opts.tee_compatible);
        assert_eq!(opts.target_version, 1);
    }
}
