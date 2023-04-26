// There seem to be false positives with pyo3
#![allow(clippy::borrow_deref_ref)]
use std::collections::HashMap;

use biscuit_auth as biscuit;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::*;

use pyo3::create_exception;

create_exception!(biscuit_auth, DataLogError, pyo3::exceptions::PyException);
create_exception!(
    biscuit_auth,
    AuthorizationError,
    pyo3::exceptions::PyException
);
create_exception!(
    biscuit_auth,
    BiscuitBuildError,
    pyo3::exceptions::PyException
);
create_exception!(
    biscuit_auth,
    BiscuitValidationError,
    pyo3::exceptions::PyException
);
create_exception!(
    biscuit_auth,
    BiscuitSerializationError,
    pyo3::exceptions::PyException
);
create_exception!(
    biscuit_auth,
    BiscuitBlockError,
    pyo3::exceptions::PyException
);

#[pyclass(name = "BiscuitBuilder")]
pub struct PyBiscuitBuilder(biscuit::builder::BiscuitBuilder);

#[pymethods]
impl PyBiscuitBuilder {
    #[new]
    fn new() -> PyBiscuitBuilder {
        PyBiscuitBuilder(biscuit::builder::BiscuitBuilder::new())
    }

    pub fn build(&self, root: &PyPrivateKey) -> PyResult<PyBiscuit> {
        let keypair = biscuit::KeyPair::from(&root.0);
        Ok(PyBiscuit(
            self.0
                .clone()
                .build(&keypair)
                .map_err(|e| BiscuitBuildError::new_err(e.to_string()))?,
        ))
    }

    pub fn add_code(&mut self, source: &str) -> PyResult<()> {
        self.0
            .add_code(source)
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    // todo: support for public keys
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        parameters: HashMap<String, PyTerm>,
        // scope_parameters: HashMap<String, PyPublicKey>,
    ) -> PyResult<()> {
        let parameters = parameters
            .into_iter()
            .map(|(k, t)| (k, t.to_term()))
            .collect::<HashMap<_, _>>();

        /*
        let scope_parameters = scope_parameters
            .into_iter()
            .map(|(k, p)| (k, p.0))
            .collect::<HashMap<_, _>>();
        */

        self.0
            .add_code_with_params(source, parameters, HashMap::default())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    pub fn add_fact(&mut self, _fact: &PyFact) -> PyResult<()> {
        todo!()
    }

    pub fn add_rule(&mut self, _rule: &PyRule) -> PyResult<()> {
        todo!()
    }

    pub fn add_check(&mut self, _check: &PyCheck) -> PyResult<()> {
        todo!()
    }

    pub fn merge(&mut self, _builder: &PyBlockBuilder) -> PyResult<()> {
        todo!()
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

#[pyclass(name = "Biscuit")]
pub struct PyBiscuit(biscuit::Biscuit);

#[pymethods]
impl PyBiscuit {
    /// Creates a BiscuitBuilder
    ///
    /// the builder can then create a new token with a root key
    #[staticmethod]
    pub fn builder() -> PyBiscuitBuilder {
        PyBiscuitBuilder::new()
    }

    /// Deserializes a token from raw data
    ///
    /// This will check the signature using the root key
    #[classmethod]
    pub fn from_bytes(_: &PyType, data: &[u8], root: &PyPublicKey) -> PyResult<PyBiscuit> {
        match biscuit::Biscuit::from(data, root.0) {
            Ok(biscuit) => Ok(PyBiscuit(biscuit)),
            Err(error) => Err(BiscuitValidationError::new_err(error.to_string())),
        }
    }

    /// Deserializes a token from URL safe base 64 data
    ///
    /// This will check the signature using the root key
    ///
    #[classmethod]
    pub fn from_base64(_: &PyType, data: &[u8], root: &PyPublicKey) -> PyResult<PyBiscuit> {
        match biscuit::Biscuit::from_base64(data, root.0) {
            Ok(biscuit) => Ok(PyBiscuit(biscuit)),
            Err(error) => Err(BiscuitValidationError::new_err(error.to_string())),
        }
    }

    /// Serializes to raw data
    pub fn to_bytes(&self) -> PyResult<Vec<u8>> {
        match self.0.to_vec() {
            Ok(vec) => Ok(vec),
            Err(error) => Err(BiscuitSerializationError::new_err(error.to_string())),
        }
    }

    /// Serializes to URL safe base 64 data
    pub fn to_base64(&self) -> String {
        self.0.to_base64().unwrap()
    }

    // TODO Revocation IDs

    /// Returns the number of blocks in the token
    pub fn block_count(&self) -> usize {
        self.0.block_count()
    }

    /// Prints a block's content as Datalog code
    pub fn block_source(&self, index: usize) -> PyResult<String> {
        self.0
            .print_block_source(index)
            .map_err(|e| BiscuitBlockError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        self.0.print()
    }
}

/// The Authorizer verifies a request according to its policies and the provided token
#[pyclass(name = "Authorizer")]
pub struct PyAuthorizer(biscuit::Authorizer);

#[pymethods]
impl PyAuthorizer {
    #[new]
    pub fn new() -> PyAuthorizer {
        PyAuthorizer(biscuit::Authorizer::new())
    }

    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        _parameters: HashMap<String, PyTerm>,
    ) -> PyResult<()> {
        self.0
            .add_code_with_params(source, HashMap::default(), HashMap::default())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    pub fn add_fact(&mut self, _fact: &PyFact) -> PyResult<()> {
        todo!()
    }

    pub fn add_rule(&mut self, _rule: &PyRule) -> PyResult<()> {
        todo!()
    }

    pub fn add_check(&mut self, _check: &PyCheck) -> PyResult<()> {
        todo!()
    }

    pub fn add_policy(&mut self, _policy: &PyPolicy) -> PyResult<()> {
        todo!()
    }

    pub fn merge(&mut self, _builder: &PyAuthorizer) -> PyResult<()> {
        todo!()
    }

    pub fn merge_block(&mut self, _builder: &PyBlockBuilder) -> PyResult<()> {
        todo!()
    }

    /// Runs the authorization checks and policies
    ///
    /// Returns the index of the matching allow policy, or an error containing the matching deny
    /// policy or a list of the failing checks
    pub fn authorize(&mut self) -> PyResult<usize> {
        self.0
            .authorize()
            .map_err(|error| AuthorizationError::new_err(error.to_string()))
    }
}

impl Default for PyAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a block to attenuate a token
#[pyclass(name = "BlockBuilder")]
#[derive(Clone)]
pub struct PyBlockBuilder(biscuit::builder::BlockBuilder);

#[pymethods]
impl PyBlockBuilder {
    pub fn add_fact(&mut self, _fact: &PyFact) -> PyResult<()> {
        todo!()
    }

    pub fn add_rule(&mut self, _rule: &PyRule) -> PyResult<()> {
        todo!()
    }

    pub fn add_check(&mut self, _check: &PyCheck) -> PyResult<()> {
        todo!()
    }

    pub fn add_policy(&mut self, _policy: &PyPolicy) -> PyResult<()> {
        todo!()
    }

    pub fn merge(&mut self, _builder: &PyAuthorizer) -> PyResult<()> {
        todo!()
    }

    /// Adds facts, rules, checks and policies as one code block
    pub fn add_code(&mut self, source: &str) -> PyResult<()> {
        match self.0.add_code(source) {
            Ok(_) => Ok(()),
            Err(error) => Err(DataLogError::new_err(error.to_string())),
        }
    }
}

#[pyclass(name = "KeyPair")]
pub struct PyKeyPair(biscuit::KeyPair);

#[pymethods]
impl PyKeyPair {
    #[new]
    pub fn new() -> Self {
        PyKeyPair(biscuit::KeyPair::new())
    }

    #[classmethod]
    pub fn from_private_key(_: &PyType, private_key: PyPrivateKey) -> Self {
        PyKeyPair(biscuit::KeyPair::from(&private_key.0))
    }

    #[getter]
    pub fn public_key(&self) -> PyPublicKey {
        PyPublicKey(self.0.public())
    }

    #[getter]
    pub fn private_key(&self) -> PyPrivateKey {
        PyPrivateKey(self.0.private())
    }
}

impl Default for PyKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Public key
#[pyclass(name = "PublicKey")]
pub struct PyPublicKey(biscuit::PublicKey);

#[pymethods]
impl PyPublicKey {
    /// Serializes a public key to raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Serializes a public key to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Deserializes a public key from raw bytes
    #[classmethod]
    pub fn from_bytes(_: &PyType, data: &[u8]) -> PyResult<PyPublicKey> {
        match biscuit::PublicKey::from_bytes(data) {
            Ok(key) => Ok(PyPublicKey(key)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    /// Deserializes a public key from a hexadecimal string
    #[classmethod]
    pub fn from_hex(_: &PyType, data: &str) -> PyResult<PyPublicKey> {
        let data = match hex::decode(data) {
            Ok(data) => data,
            Err(error) => return Err(PyValueError::new_err(error.to_string())),
        };
        match biscuit::PublicKey::from_bytes(&data) {
            Ok(key) => Ok(PyPublicKey(key)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }
}

#[pyclass(name = "PrivateKey")]
#[derive(Clone)]
pub struct PyPrivateKey(biscuit::PrivateKey);

#[pymethods]
impl PyPrivateKey {
    /// Serializes a private key to raw bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Serializes a private key to a hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.to_bytes())
    }

    /// Deserializes a private key from raw bytes
    #[classmethod]
    pub fn from_bytes(_: &PyType, data: &[u8]) -> PyResult<PyPrivateKey> {
        match biscuit::PrivateKey::from_bytes(data) {
            Ok(key) => Ok(PyPrivateKey(key)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }

    /// Deserializes a private key from a hexadecimal string
    #[classmethod]
    pub fn from_hex(_: &PyType, data: &str) -> PyResult<PyPrivateKey> {
        let data = match hex::decode(data) {
            Ok(data) => data,
            Err(error) => return Err(PyValueError::new_err(error.to_string())),
        };
        match biscuit::PrivateKey::from_bytes(&data) {
            Ok(key) => Ok(PyPrivateKey(key)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }
}

/// Term values passed from python-land.
#[derive(FromPyObject)]
pub enum PyTerm {
    Integer(i64),
    Str(String),
    // Date(&'a PyDateTime),
    Bytes(Vec<u8>),
    Bool(bool),
    // Set(BTreeSet<Box<PyTerm>>),
}

impl PyTerm {
    pub fn to_term(&self) -> biscuit::builder::Term {
        match self {
            PyTerm::Integer(i) => (*i).into(),
            PyTerm::Str(s) => biscuit::builder::Term::Str(s.to_string()),
            PyTerm::Bytes(b) => b.clone().into(),
            PyTerm::Bool(b) => (*b).into(),
        }
    }
}

#[pyclass(name = "Fact")]
pub struct PyFact(biscuit_auth::builder::Fact);

#[pymethods]
impl PyFact {
    #[new]
    pub fn new(_source: &str, _parameters: HashMap<String, PyTerm>) -> PyResult<Self> {
        todo!()
    }
}

#[pyclass(name = "Rule")]
pub struct PyRule(biscuit_auth::builder::Rule);

#[pymethods]
impl PyRule {
    #[new]
    pub fn new(_source: &str, _parameters: HashMap<String, PyTerm>) -> PyResult<Self> {
        todo!()
    }
}

#[pyclass(name = "Check")]
pub struct PyCheck(biscuit_auth::builder::Check);

#[pymethods]
impl PyCheck {
    #[new]
    pub fn new(_source: &str, _parameters: HashMap<String, PyTerm>) -> PyResult<Self> {
        todo!()
    }
}

#[pyclass(name = "Policy")]
pub struct PyPolicy(biscuit_auth::builder::Policy);

#[pymethods]
impl PyPolicy {
    #[new]
    pub fn new(_source: &str, _parameters: HashMap<String, PyTerm>) -> PyResult<Self> {
        todo!()
    }
}

#[pymodule]
fn biscuit_auth(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyKeyPair>()?;
    m.add_class::<PyPublicKey>()?;
    m.add_class::<PyPrivateKey>()?;
    m.add_class::<PyBiscuit>()?;
    m.add_class::<PyBiscuitBuilder>()?;
    m.add_class::<PyBlockBuilder>()?;
    m.add_class::<PyAuthorizer>()?;
    m.add_class::<PyFact>()?;
    m.add_class::<PyRule>()?;
    m.add_class::<PyCheck>()?;
    m.add_class::<PyPolicy>()?;

    m.add("DataLogError", py.get_type::<DataLogError>())?;
    m.add("AuthorizationError", py.get_type::<AuthorizationError>())?;
    m.add("BiscuitBuildError", py.get_type::<BiscuitBuildError>())?;
    m.add("BiscuitBlockError", py.get_type::<BiscuitBlockError>())?;
    m.add(
        "BiscuitValidationError",
        py.get_type::<BiscuitValidationError>(),
    )?;
    m.add(
        "BiscuitSerializationError",
        py.get_type::<BiscuitSerializationError>(),
    )?;

    Ok(())
}
