use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

use crate::error::{AevorError, Result};

/// Function parameter types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamType {
    /// Boolean type
    Bool,
    
    /// 8-bit unsigned integer
    U8,
    
    /// 64-bit unsigned integer
    U64,
    
    /// 128-bit unsigned integer
    U128,
    
    /// Address type (account address)
    Address,
    
    /// Vector of a specific type
    Vector(Box<ParamType>),
    
    /// Struct type with a name
    Struct(String),
    
    /// Signer type (special type for transaction senders)
    Signer,
    
    /// Generic type parameter
    TypeParam(String),
    
    /// Reference type (borrowed)
    Reference(Box<ParamType>),
    
    /// Mutable reference type
    MutableReference(Box<ParamType>),
}

impl ParamType {
    /// Get the string representation of this type
    pub fn to_string(&self) -> String {
        match self {
            ParamType::Bool => "bool".to_string(),
            ParamType::U8 => "u8".to_string(),
            ParamType::U64 => "u64".to_string(),
            ParamType::U128 => "u128".to_string(),
            ParamType::Address => "address".to_string(),
            ParamType::Vector(elem_type) => format!("vector<{}>", elem_type.to_string()),
            ParamType::Struct(name) => name.clone(),
            ParamType::Signer => "signer".to_string(),
            ParamType::TypeParam(name) => name.clone(),
            ParamType::Reference(inner_type) => format!("&{}", inner_type.to_string()),
            ParamType::MutableReference(inner_type) => format!("&mut {}", inner_type.to_string()),
        }
    }
    
    /// Parse a type from its string representation
    pub fn from_string(s: &str) -> Result<Self> {
        if s == "bool" {
            Ok(ParamType::Bool)
        } else if s == "u8" {
            Ok(ParamType::U8)
        } else if s == "u64" {
            Ok(ParamType::U64)
        } else if s == "u128" {
            Ok(ParamType::U128)
        } else if s == "address" {
            Ok(ParamType::Address)
        } else if s == "signer" {
            Ok(ParamType::Signer)
        } else if s.starts_with("vector<") && s.ends_with(">") {
            let elem_type = &s[7..s.len() - 1];
            Ok(ParamType::Vector(Box::new(ParamType::from_string(elem_type)?)))
        } else if s.starts_with("&mut ") {
            let inner_type = &s[5..];
            Ok(ParamType::MutableReference(Box::new(ParamType::from_string(inner_type)?)))
        } else if s.starts_with("&") {
            let inner_type = &s[1..];
            Ok(ParamType::Reference(Box::new(ParamType::from_string(inner_type)?)))
        } else if s.contains("::") {
            // Assuming it's a struct type
            Ok(ParamType::Struct(s.to_string()))
        } else {
            // Assuming it's a type parameter
            Ok(ParamType::TypeParam(s.to_string()))
        }
    }
    
    /// Check if this is a primitive type
    pub fn is_primitive(&self) -> bool {
        matches!(self, ParamType::Bool | ParamType::U8 | ParamType::U64 | ParamType::U128)
    }
    
    /// Check if this is a reference type
    pub fn is_reference(&self) -> bool {
        matches!(self, ParamType::Reference(_) | ParamType::MutableReference(_))
    }
    
    /// Check if this is a mutable reference
    pub fn is_mutable_reference(&self) -> bool {
        matches!(self, ParamType::MutableReference(_))
    }
}

/// Function visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Visibility {
    /// Public: Can be called by anyone
    Public,
    
    /// Friend: Can be called by modules marked as friends
    Friend,
    
    /// Private: Can only be called from within the same module
    Private,
}

impl Visibility {
    /// Convert visibility to a string
    pub fn to_string(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Friend => "friend",
            Visibility::Private => "private",
        }
    }
    
    /// Parse visibility from a string
    pub fn from_string(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "public" => Ok(Visibility::Public),
            "friend" => Ok(Visibility::Friend),
            "private" => Ok(Visibility::Private),
            _ => Err(AevorError::vm(format!("Invalid visibility: {}", s))),
        }
    }
}

/// Function definition
#[derive(Clone, Serialize, Deserialize)]
pub struct Function {
    /// Function name
    pub name: String,
    
    /// Function visibility
    pub visibility: Visibility,
    
    /// Function parameters
    pub params: Vec<ParamType>,
    
    /// Function return types
    pub returns: Vec<ParamType>,
    
    /// Whether this function is read-only (doesn't modify state)
    pub read_only: bool,
    
    /// Bytecode offset for this function
    pub offset: usize,
    
    /// Function bytecode (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytecode: Option<Vec<u8>>,
}

impl Function {
    /// Create a new function definition
    pub fn new(
        name: String,
        visibility: Visibility,
        params: Vec<ParamType>,
        returns: Vec<ParamType>,
        read_only: bool,
        offset: usize,
    ) -> Self {
        Self {
            name,
            visibility,
            params,
            returns,
            read_only,
            offset,
            bytecode: None,
        }
    }
    
    /// Get the function signature as a string
    pub fn signature(&self) -> String {
        let params = self.params
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        
        let returns = if self.returns.is_empty() {
            "".to_string()
        } else {
            let ret_types = self.returns
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!(": ({})", ret_types)
        };
        
        format!("{}({}){}",
            self.name,
            params,
            returns,
        )
    }
    
    /// Set the function bytecode
    pub fn with_bytecode(mut self, bytecode: Vec<u8>) -> Self {
        self.bytecode = Some(bytecode);
        self
    }
    
    /// Check if this function can be called externally (public or friend)
    pub fn is_external(&self) -> bool {
        matches!(self.visibility, Visibility::Public | Visibility::Friend)
    }
}

impl fmt::Debug for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Function")
            .field("name", &self.name)
            .field("visibility", &self.visibility)
            .field("params", &self.params.iter().map(|p| p.to_string()).collect::<Vec<_>>())
            .field("returns", &self.returns.iter().map(|r| r.to_string()).collect::<Vec<_>>())
            .field("read_only", &self.read_only)
            .field("offset", &self.offset)
            .field("bytecode_size", &self.bytecode.as_ref().map(|b| b.len()))
            .finish()
    }
}

/// Bytecode operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BytecodeOp {
    /// No operation
    Nop,
    
    /// Push a value onto the stack
    Push(Vec<u8>),
    
    /// Pop a value from the stack
    Pop,
    
    /// Load local variable
    LoadLocal(u8),
    
    /// Store local variable
    StoreLocal(u8),
    
    /// Load global resource
    LoadResource(Vec<u8>),
    
    /// Store global resource
    StoreResource(Vec<u8>),
    
    /// Call a function
    Call(Vec<u8>),
    
    /// Return from function
    Ret,
    
    /// Branch if condition is true
    BrTrue(u16),
    
    /// Branch if condition is false
    BrFalse(u16),
    
    /// Unconditional branch
    Branch(u16),
    
    /// Create a new struct
    Pack(Vec<u8>),
    
    /// Destroy a struct and get its fields
    Unpack(Vec<u8>),
    
    /// Copy a value
    Copy,
    
    /// Move a value
    Move,
    
    /// Abort with error code
    Abort,
    
    /// Assert condition with error code
    Assert,
    
    /// Add two values
    Add,
    
    /// Subtract two values
    Sub,
    
    /// Multiply two values
    Mul,
    
    /// Divide two values
    Div,
    
    /// Modulo operation
    Mod,
    
    /// Compare equality
    Eq,
    
    /// Compare inequality
    Neq,
    
    /// Less than comparison
    Lt,
    
    /// Greater than comparison
    Gt,
    
    /// Less than or equal comparison
    Le,
    
    /// Greater than or equal comparison
    Ge,
    
    /// Bitwise AND
    And,
    
    /// Bitwise OR
    Or,
    
    /// Bitwise XOR
    Xor,
    
    /// Bitwise NOT
    Not,
    
    /// Bitwise shift left
    Shl,
    
    /// Bitwise shift right
    Shr,
    
    /// Create a vector
    VecPack(u16),
    
    /// Get vector length
    VecLen,
    
    /// Get vector element
    VecGet,
    
    /// Set vector element
    VecSet,
    
    /// Push to vector
    VecPush,
    
    /// Pop from vector
    VecPop,
    
    /// Boolean and
    BAnd,
    
    /// Boolean or
    BOr,
    
    /// Boolean not
    BNot,
    
    /// Custom opcode
    Custom(u8, Vec<u8>),
}

/// Module bytecode
#[derive(Clone, Serialize, Deserialize)]
pub struct Bytecode {
    /// Bytecode version
    pub version: u32,
    
    /// Bytecode operations
    pub ops: Vec<BytecodeOp>,
    
    /// Raw bytecode bytes
    pub raw: Vec<u8>,
}

impl Bytecode {
    /// Create a new bytecode
    pub fn new(version: u32, ops: Vec<BytecodeOp>, raw: Vec<u8>) -> Self {
        Self {
            version,
            ops,
            raw,
        }
    }
    
    /// Parse bytecode from raw bytes
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 {
            return Err(AevorError::vm("Bytecode too short"));
        }
        
        // Extract version from first 4 bytes
        let version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        
        // Parse operations
        let mut ops = Vec::new();
        let mut i = 4;
        
        while i < raw.len() {
            let op_code = raw[i];
            i += 1;
            
            if i >= raw.len() && op_code != 0 { // Nop can be at the end
                return Err(AevorError::vm("Unexpected end of bytecode"));
            }
            
            let op = match op_code {
                0 => BytecodeOp::Nop,
                1 => {
                    // Push operation with size and data
                    if i + 2 > raw.len() {
                        return Err(AevorError::vm("Unexpected end of bytecode in Push"));
                    }
                    let size = u16::from_le_bytes([raw[i], raw[i+1]]) as usize;
                    i += 2;
                    
                    if i + size > raw.len() {
                        return Err(AevorError::vm("Unexpected end of bytecode in Push data"));
                    }
                    
                    let data = raw[i..i+size].to_vec();
                    i += size;
                    
                    BytecodeOp::Push(data)
                },
                2 => BytecodeOp::Pop,
                // Add more opcodes as needed
                // This is a simplified implementation
                
                _ => {
                    // Custom opcode
                    if i + 2 > raw.len() {
                        return Err(AevorError::vm("Unexpected end of bytecode in Custom"));
                    }
                    let size = u16::from_le_bytes([raw[i], raw[i+1]]) as usize;
                    i += 2;
                    
                    if i + size > raw.len() {
                        return Err(AevorError::vm("Unexpected end of bytecode in Custom data"));
                    }
                    
                    let data = raw[i..i+size].to_vec();
                    i += size;
                    
                    BytecodeOp::Custom(op_code, data)
                }
            };
            
            ops.push(op);
        }
        
        Ok(Self {
            version,
            ops,
            raw: raw.to_vec(),
        })
    }
    
    /// Serialize bytecode to raw bytes
    pub fn serialize(&self) -> Vec<u8> {
        // For simplicity, we'll return the existing raw bytes
        // In a real implementation, this would serialize the ops vector
        self.raw.clone()
    }
}

impl fmt::Debug for Bytecode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bytecode")
            .field("version", &self.version)
            .field("ops_count", &self.ops.len())
            .field("raw_size", &self.raw.len())
            .finish()
    }
}

/// Module dependency
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Dependency {
    /// Dependency module name
    pub name: String,
    
    /// Dependency module version
    pub version: u32,
    
    /// Dependency address (optional)
    pub address: Option<Vec<u8>>,
}

impl Dependency {
    /// Create a new dependency
    pub fn new(name: String, version: u32) -> Self {
        Self {
            name,
            version,
            address: None,
        }
    }
    
    /// Create a new dependency with an address
    pub fn with_address(name: String, version: u32, address: Vec<u8>) -> Self {
        Self {
            name,
            version,
            address: Some(address),
        }
    }
    
    /// Get dependency as a string
    pub fn to_string(&self) -> String {
        if let Some(addr) = &self.address {
            format!("{}::{}::{}", hex::encode(addr), self.name, self.version)
        } else {
            format!("{}::{}", self.name, self.version)
        }
    }
}

/// Smart contract module
#[derive(Clone, Serialize, Deserialize)]
pub struct Module {
    /// Module name
    pub name: String,
    
    /// Module version
    pub version: u32,
    
    /// Module bytecode
    pub bytecode: Vec<u8>,
    
    /// Module functions
    pub functions: HashMap<String, Function>,
    
    /// Module dependencies
    pub dependencies: Vec<Dependency>,
    
    /// Module owner address
    pub owner: Option<Vec<u8>>,
    
    /// Module metadata
    pub metadata: HashMap<String, Vec<u8>>,
    
    /// Parsed bytecode (if available)
    #[serde(skip)]
    pub parsed_bytecode: Option<Bytecode>,
}

impl Module {
    /// Create a new module
    pub fn new(name: String, version: u32, bytecode: Vec<u8>) -> Self {
        Self {
            name,
            version,
            bytecode,
            functions: HashMap::new(),
            dependencies: Vec::new(),
            owner: None,
            metadata: HashMap::new(),
            parsed_bytecode: None,
        }
    }
    
    /// Add a function to the module
    pub fn add_function(&mut self, function: Function) -> Result<()> {
        if self.functions.contains_key(&function.name) {
            return Err(AevorError::vm(format!("Function {} already exists", function.name)));
        }
        
        self.functions.insert(function.name.clone(), function);
        Ok(())
    }
    
    /// Add a dependency to the module
    pub fn add_dependency(&mut self, dependency: Dependency) -> Result<()> {
        if self.dependencies.iter().any(|d| d.name == dependency.name) {
            return Err(AevorError::vm(format!("Dependency {} already exists", dependency.name)));
        }
        
        self.dependencies.push(dependency);
        Ok(())
    }
    
    /// Get a function by name
    pub fn get_function(&self, name: &str) -> Option<&Function> {
        self.functions.get(name)
    }
    
    /// Check if the module has a function
    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }
    
    /// Get all function names
    pub fn get_function_names(&self) -> Vec<String> {
        self.functions.keys().cloned().collect()
    }
    
    /// Get a dependency by name
    pub fn get_dependency(&self, name: &str) -> Option<&Dependency> {
        self.dependencies.iter().find(|d| d.name == name)
    }
    
    /// Check if the module has a dependency
    pub fn has_dependency(&self, name: &str) -> bool {
        self.dependencies.iter().any(|d| d.name == name)
    }
    
    /// Parse the bytecode
    pub fn parse_bytecode(&mut self) -> Result<()> {
        self.parsed_bytecode = Some(Bytecode::parse(&self.bytecode)?);
        Ok(())
    }
    
    /// Get the parsed bytecode
    pub fn get_parsed_bytecode(&mut self) -> Result<&Bytecode> {
        if self.parsed_bytecode.is_none() {
            self.parse_bytecode()?;
        }
        
        Ok(self.parsed_bytecode.as_ref().unwrap())
    }
    
    /// Set the module owner
    pub fn with_owner(mut self, owner: Vec<u8>) -> Self {
        self.owner = Some(owner);
        self
    }
    
    /// Add metadata to the module
    pub fn add_metadata(&mut self, key: String, value: Vec<u8>) {
        self.metadata.insert(key, value);
    }
    
    /// Get module ID (name:version)
    pub fn id(&self) -> String {
        format!("{}:{}", self.name, self.version)
    }
    
    /// Get full module ID including owner if available
    pub fn full_id(&self) -> String {
        if let Some(owner) = &self.owner {
            format!("{}::{}:{}", hex::encode(owner), self.name, self.version)
        } else {
            self.id()
        }
    }
}

impl fmt::Debug for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("bytecode_size", &self.bytecode.len())
            .field("functions", &self.functions.keys().collect::<Vec<_>>())
            .field("dependencies", &self.dependencies)
            .field("owner", &self.owner.as_ref().map(hex::encode))
            .field("metadata", &self.metadata.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Module builder for creating modules
pub struct ModuleBuilder {
    /// Module name
    name: String,
    
    /// Module version
    version: u32,
    
    /// Module bytecode
    bytecode: Vec<u8>,
    
    /// Module functions
    functions: Vec<Function>,
    
    /// Module dependencies
    dependencies: Vec<Dependency>,
    
    /// Module owner
    owner: Option<Vec<u8>>,
    
    /// Module metadata
    metadata: HashMap<String, Vec<u8>>,
}

impl ModuleBuilder {
    /// Create a new module builder
    pub fn new(name: String, version: u32, bytecode: Vec<u8>) -> Self {
        Self {
            name,
            version,
            bytecode,
            functions: Vec::new(),
            dependencies: Vec::new(),
            owner: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Add a function to the module
    pub fn function(mut self, function: Function) -> Self {
        self.functions.push(function);
        self
    }
    
    /// Add a dependency to the module
    pub fn dependency(mut self, dependency: Dependency) -> Self {
        self.dependencies.push(dependency);
        self
    }
    
    /// Set the module owner
    pub fn owner(mut self, owner: Vec<u8>) -> Self {
        self.owner = Some(owner);
        self
    }
    
    /// Add metadata to the module
    pub fn metadata(mut self, key: String, value: Vec<u8>) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Build the module
    pub fn build(self) -> Result<Module> {
        let mut module = Module::new(self.name, self.version, self.bytecode);
        
        if let Some(owner) = self.owner {
            module.owner = Some(owner);
        }
        
        // Add functions
        for function in self.functions {
            module.add_function(function)?;
        }
        
        // Add dependencies
        for dependency in self.dependencies {
            module.add_dependency(dependency)?;
        }
        
        // Add metadata
        for (key, value) in self.metadata {
            module.add_metadata(key, value);
        }
        
        Ok(module)
    }
}

/// Parse bytecode from binary format
pub fn parse_bytecode(raw: &[u8]) -> Result<Bytecode> {
    Bytecode::parse(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_param_type_to_string() {
        assert_eq!(ParamType::Bool.to_string(), "bool");
        assert_eq!(ParamType::U8.to_string(), "u8");
        assert_eq!(ParamType::U64.to_string(), "u64");
        assert_eq!(ParamType::U128.to_string(), "u128");
        assert_eq!(ParamType::Address.to_string(), "address");
        assert_eq!(ParamType::Signer.to_string(), "signer");
        assert_eq!(ParamType::Vector(Box::new(ParamType::U8)).to_string(), "vector<u8>");
        assert_eq!(ParamType::Struct("MyStruct".to_string()).to_string(), "MyStruct");
        assert_eq!(ParamType::TypeParam("T".to_string()).to_string(), "T");
        assert_eq!(ParamType::Reference(Box::new(ParamType::U64)).to_string(), "&u64");
        assert_eq!(ParamType::MutableReference(Box::new(ParamType::U64)).to_string(), "&mut u64");
    }
    
    #[test]
    fn test_param_type_from_string() {
        assert_eq!(ParamType::from_string("bool").unwrap(), ParamType::Bool);
        assert_eq!(ParamType::from_string("u8").unwrap(), ParamType::U8);
        assert_eq!(ParamType::from_string("u64").unwrap(), ParamType::U64);
        assert_eq!(ParamType::from_string("u128").unwrap(), ParamType::U128);
        assert_eq!(ParamType::from_string("address").unwrap(), ParamType::Address);
        assert_eq!(ParamType::from_string("signer").unwrap(), ParamType::Signer);
        assert_eq!(ParamType::from_string("vector<u8>").unwrap(), ParamType::Vector(Box::new(ParamType::U8)));
        assert_eq!(ParamType::from_string("Foo::Bar").unwrap(), ParamType::Struct("Foo::Bar".to_string()));
        assert_eq!(ParamType::from_string("T").unwrap(), ParamType::TypeParam("T".to_string()));
        assert_eq!(ParamType::from_string("&u64").unwrap(), ParamType::Reference(Box::new(ParamType::U64)));
        assert_eq!(ParamType::from_string("&mut u64").unwrap(), ParamType::MutableReference(Box::new(ParamType::U64)));
    }
    
    #[test]
    fn test_visibility() {
        assert_eq!(Visibility::Public.to_string(), "public");
        assert_eq!(Visibility::Friend.to_string(), "friend");
        assert_eq!(Visibility::Private.to_string(), "private");
        
        assert_eq!(Visibility::from_string("public").unwrap(), Visibility::Public);
        assert_eq!(Visibility::from_string("friend").unwrap(), Visibility::Friend);
        assert_eq!(Visibility::from_string("private").unwrap(), Visibility::Private);
        
        assert!(Visibility::from_string("invalid").is_err());
    }
    
    #[test]
    fn test_function_signature() {
        let function = Function::new(
            "transfer".to_string(),
            Visibility::Public,
            vec![
                ParamType::Address,
                ParamType::U64,
            ],
            vec![
                ParamType::Bool,
            ],
            false,
            0,
        );
        
        assert_eq!(function.signature(), "transfer(address, u64): (bool)");
        
        let void_function = Function::new(
            "initialize".to_string(),
            Visibility::Public,
            vec![
                ParamType::Signer,
            ],
            vec![],
            false,
            0,
        );
        
        assert_eq!(void_function.signature(), "initialize(signer)");
    }
    
    #[test]
    fn test_bytecode_parse() {
        // Create a simple bytecode: version 1, Nop, Push [1, 2, 3], Pop
        let raw = vec![
            1, 0, 0, 0,  // Version 1
            0,           // Nop
            1, 3, 0,     // Push with size 3
            1, 2, 3,     // Push data
            2,           // Pop
        ];
        
        let bytecode = Bytecode::parse(&raw).unwrap();
        assert_eq!(bytecode.version, 1);
        assert_eq!(bytecode.ops.len(), 3);
        assert_eq!(bytecode.ops[0], BytecodeOp::Nop);
        assert_eq!(bytecode.ops[1], BytecodeOp::Push(vec![1, 2, 3]));
        assert_eq!(bytecode.ops[2], BytecodeOp::Pop);
        
        // Test with invalid bytecode
        assert!(Bytecode::parse(&[]).is_err());
        assert!(Bytecode::parse(&[1, 0, 0]).is_err());
    }
    
    #[test]
    fn test_dependency() {
        let dep = Dependency::new("MyModule".to_string(), 1);
        assert_eq!(dep.name, "MyModule");
        assert_eq!(dep.version, 1);
        assert_eq!(dep.address, None);
        assert_eq!(dep.to_string(), "MyModule::1");
        
        let addr = vec![1, 2, 3, 4];
        let dep_with_addr = Dependency::with_address("MyModule".to_string(), 1, addr.clone());
        assert_eq!(dep_with_addr.address, Some(addr.clone()));
        assert_eq!(dep_with_addr.to_string(), format!("{}::MyModule::1", hex::encode(&addr)));
    }
    
    #[test]
    fn test_module() {
        let bytecode = vec![1, 2, 3, 4];
        let mut module = Module::new("MyModule".to_string(), 1, bytecode.clone());
        
        // Test basic properties
        assert_eq!(module.name, "MyModule");
        assert_eq!(module.version, 1);
        assert_eq!(module.bytecode, bytecode);
        assert!(module.functions.is_empty());
        assert!(module.dependencies.is_empty());
        assert_eq!(module.owner, None);
        
        // Add a function
        let function = Function::new(
            "transfer".to_string(),
            Visibility::Public,
            vec![ParamType::Address, ParamType::U64],
            vec![ParamType::Bool],
            false,
            0,
        );
        
        module.add_function(function.clone()).unwrap();
        assert_eq!(module.functions.len(), 1);
        assert!(module.has_function("transfer"));
        assert_eq!(module.get_function("transfer").unwrap().signature(), "transfer(address, u64): (bool)");
        
        // Try to add the same function again (should fail)
        assert!(module.add_function(function).is_err());
        
        // Add a dependency
        let dependency = Dependency::new("OtherModule".to_string(), 1);
        module.add_dependency(dependency.clone()).unwrap();
        assert_eq!(module.dependencies.len(), 1);
        assert!(module.has_dependency("OtherModule"));
        assert_eq!(module.get_dependency("OtherModule").unwrap().name, "OtherModule");
        
        // Try to add the same dependency again (should fail)
        assert!(module.add_dependency(dependency).is_err());
        
        // Test IDs
        assert_eq!(module.id(), "MyModule:1");
        assert_eq!(module.full_id(), "MyModule:1");
        
        // Set owner
        let owner = vec![1, 2, 3, 4];
        let module_with_owner = module.with_owner(owner.clone());
        assert_eq!(module_with_owner.owner, Some(owner.clone()));
        assert_eq!(module_with_owner.full_id(), format!("{}::MyModule:1", hex::encode(&owner)));
    }
    
    #[test]
    fn test_module_builder() {
        let bytecode = vec![1, 2, 3, 4];
        
        let function = Function::new(
            "transfer".to_string(),
            Visibility::Public,
            vec![ParamType::Address, ParamType::U64],
            vec![ParamType::Bool],
            false,
            0,
        );
        
        let dependency = Dependency::new("OtherModule".to_string(), 1);
        let owner = vec![1, 2, 3, 4];
        
        let module = ModuleBuilder::new("MyModule".to_string(), 1, bytecode.clone())
            .function(function.clone())
            .dependency(dependency.clone())
            .owner(owner.clone())
            .metadata("author".to_string(), b"John Doe".to_vec())
            .build()
            .unwrap();
        
        assert_eq!(module.name, "MyModule");
        assert_eq!(module.version, 1);
        assert_eq!(module.bytecode, bytecode);
        assert_eq!(module.functions.len(), 1);
        assert_eq!(module.dependencies.len(), 1);
        assert_eq!(module.owner, Some(owner));
        assert_eq!(module.metadata.len(), 1);
        assert_eq!(module.metadata.get("author").unwrap(), b"John Doe");
    }
}
