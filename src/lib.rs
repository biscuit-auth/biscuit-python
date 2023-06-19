// There seem to be false positives with pyo3
#![allow(clippy::borrow_deref_ref)]
use ::biscuit_auth::RootKeyProvider;
use chrono::DateTime;
use chrono::TimeZone;
use chrono::Utc;
use std::collections::BTreeSet;
use std::collections::HashMap;

use ::biscuit_auth::{builder, error, Authorizer, Biscuit, KeyPair, PrivateKey, PublicKey};

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

struct PyKeyProvider {
    py_value: PyObject,
}

impl RootKeyProvider for PyKeyProvider {
    fn choose(&self, kid: Option<u32>) -> Result<PublicKey, error::Format> {
        Python::with_gil(|py| {
            if self.py_value.as_ref(py).is_callable() {
                let result = self
                    .py_value
                    .call1(py, (kid,))
                    .map_err(|_| error::Format::UnknownPublicKey)?;
                let py_pk: PyPublicKey = result
                    .extract(py)
                    .map_err(|_| error::Format::UnknownPublicKey)?;
                Ok(py_pk.0)
            } else {
                let py_pk: PyPublicKey = self
                    .py_value
                    .extract(py)
                    .map_err(|_| error::Format::UnknownPublicKey)?;
                Ok(py_pk.0)
            }
        })
    }
}

/// Builder class allowing to create a biscuit from a datalog block
///
/// :param source: a datalog snippet
#[pyclass(name = "BiscuitBuilder")]
pub struct PyBiscuitBuilder(builder::BiscuitBuilder);

#[pymethods]
impl PyBiscuitBuilder {
    /// Create a builder from a datalog snippet and optional parameter values
    #[new]
    fn new(
        source: Option<String>,
        parameters: Option<HashMap<String, PyTerm>>,
        scope_parameters: Option<HashMap<String, PyPublicKey>>,
    ) -> PyResult<PyBiscuitBuilder> {
        let mut builder = PyBiscuitBuilder(builder::BiscuitBuilder::new());
        if let Some(source) = source {
            builder.add_code_with_parameters(
                &source,
                parameters.unwrap_or_default(),
                scope_parameters.unwrap_or_default(),
            )?;
        }
        Ok(builder)
    }

    /// Build a biscuit token, using the provided private key to sign the authority block
    ///
    /// :param root: a keypair that will be used to sign the authority block
    /// :return: a biscuit token
    pub fn build(&self, root: &PyPrivateKey) -> PyResult<PyBiscuit> {
        let keypair = KeyPair::from(&root.0);
        Ok(PyBiscuit(
            self.0
                .clone()
                .build(&keypair)
                .map_err(|e| BiscuitBuildError::new_err(e.to_string()))?,
        ))
    }

    /// Add code to the builder. This code snippet cannot contain parameters. See
    /// `add_code_with_parameters` if you need to provide parameters
    pub fn add_code(&mut self, source: &str) -> PyResult<()> {
        self.0
            .add_code(source)
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add code to the builder, using the provided parameters.
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        raw_parameters: HashMap<String, PyTerm>,
        scope_parameters: HashMap<String, PyPublicKey>,
    ) -> PyResult<()> {
        let mut parameters = HashMap::new();

        for (k, raw_value) in raw_parameters {
            parameters.insert(k, raw_value.to_term()?);
        }

        let scope_parameters = scope_parameters
            .iter()
            .map(|(k, v)| (k.to_string(), v.0))
            .collect();

        self.0
            .add_code_with_params(source, parameters, scope_parameters)
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single fact to the builder. A single fact can be built with
    /// the `Fact` class and its constructor
    pub fn add_fact(&mut self, fact: &PyFact) -> PyResult<()> {
        self.0
            .add_fact(fact.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single rule to the builder. A single rule can be built with
    /// the `Rule` class and its constructor
    pub fn add_rule(&mut self, rule: &PyRule) -> PyResult<()> {
        self.0
            .add_rule(rule.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single check to the builder. A single check can be built with
    /// the `Check` class and its constructor
    pub fn add_check(&mut self, check: &PyCheck) -> PyResult<()> {
        self.0
            .add_check(check.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Merge a `BlockBuilder` in this `BiscuitBuilder`. The `BlockBuilder` will not be modified
    pub fn merge(&mut self, builder: &PyBlockBuilder) {
        self.0.merge(builder.0.clone())
    }

    pub fn set_root_key_id(&mut self, root_key_id: u32) {
        self.0.set_root_key_id(root_key_id)
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// Representation of a biscuit token that has been parsed and cryptographically verified.
#[pyclass(name = "Biscuit")]
pub struct PyBiscuit(Biscuit);

#[pymethods]
impl PyBiscuit {
    /// Creates a BiscuitBuilder
    ///
    /// the builder can then create a new token with a root key
    #[staticmethod]
    pub fn builder() -> PyResult<PyBiscuitBuilder> {
        PyBiscuitBuilder::new(None, None, None)
    }

    /// Deserializes a token from raw data
    ///
    /// This will check the signature using the provided root key (or function)
    ///
    /// :param data: a (url-safe) base64-encoded string
    /// :param root: either a public key or a function taking an integer (or `None`) and returning an public key
    #[classmethod]
    pub fn from_bytes(_: &PyType, data: &[u8], root: PyObject) -> PyResult<PyBiscuit> {
        match Biscuit::from(data, PyKeyProvider { py_value: root }) {
            Ok(biscuit) => Ok(PyBiscuit(biscuit)),
            Err(error) => Err(BiscuitValidationError::new_err(error.to_string())),
        }
    }

    /// Deserializes a token from URL safe base 64 data
    ///
    /// This will check the signature using the provided root key (or function)
    ///
    /// :param data: a (url-safe) base64-encoded string
    /// :param root: either a public key or a function taking an integer (or `None`) and returning an public key
    #[classmethod]
    pub fn from_base64(_: &PyType, data: &str, root: PyObject) -> PyResult<PyBiscuit> {
        match Biscuit::from_base64(data, PyKeyProvider { py_value: root }) {
            Ok(biscuit) => Ok(PyBiscuit(biscuit)),
            Err(error) => Err(BiscuitValidationError::new_err(error.to_string())),
        }
    }

    /// Serializes to raw bytes
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

    /// Create a new `Biscuit` by appending an attenuation block
    pub fn append(&self, block: &PyBlockBuilder) -> PyResult<PyBiscuit> {
        self.0
            .append(block.0.clone())
            .map_err(|e| BiscuitBuildError::new_err(e.to_string()))
            .map(PyBiscuit)
    }

    fn __repr__(&self) -> String {
        self.0.print()
    }
}

/// The Authorizer verifies a request according to its policies and the provided token
#[pyclass(name = "Authorizer")]
pub struct PyAuthorizer(Authorizer);

#[pymethods]
impl PyAuthorizer {
    /// Create a new authorizer from a datalog snippet and optional parameter values
    #[new]
    pub fn new(
        source: Option<String>,
        parameters: Option<HashMap<String, PyTerm>>,
        scope_parameters: Option<HashMap<String, PyPublicKey>>,
    ) -> PyResult<PyAuthorizer> {
        let mut builder = PyAuthorizer(Authorizer::new());
        if let Some(source) = source {
            builder.add_code_with_parameters(
                &source,
                parameters.unwrap_or_default(),
                scope_parameters.unwrap_or_default(),
            )?;
        }
        Ok(builder)
    }

    /// Add code to the builder, using the provided parameters.
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        raw_parameters: HashMap<String, PyTerm>,
        scope_parameters: HashMap<String, PyPublicKey>,
    ) -> PyResult<()> {
        let mut parameters = HashMap::new();

        for (k, raw_value) in raw_parameters {
            parameters.insert(k, raw_value.to_term()?);
        }

        let scope_parameters = scope_parameters
            .iter()
            .map(|(k, v)| (k.to_string(), v.0))
            .collect();

        self.0
            .add_code_with_params(source, parameters, scope_parameters)
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single fact to the authorizer. A single fact can be built with
    /// the `Fact` class and its constructor
    pub fn add_fact(&mut self, fact: &PyFact) -> PyResult<()> {
        self.0
            .add_fact(fact.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single rule to the authorizer. A single rule can be built with
    /// the `Rule` class and its constructor
    pub fn add_rule(&mut self, rule: &PyRule) -> PyResult<()> {
        self.0
            .add_rule(rule.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single check to the authorizer. A single check can be built with
    /// the `Check` class and its constructor
    pub fn add_check(&mut self, check: &PyCheck) -> PyResult<()> {
        self.0
            .add_check(check.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single policy to the authorizer. A single policy can be built with
    /// the `Policy` class and its constructor
    pub fn add_policy(&mut self, policy: &PyPolicy) -> PyResult<()> {
        self.0
            .add_policy(policy.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Merge another `Authorizer` in this `Authorizer`. The `BlockBuilder` will not be modified
    pub fn merge(&mut self, builder: &PyAuthorizer) {
        self.0.merge(builder.0.clone())
    }

    /// Merge a `BlockBuilder` in this `Authorizer`. The `BlockBuilder` will not be modified
    pub fn merge_block(&mut self, builder: &PyBlockBuilder) {
        self.0.merge_block(builder.0.clone())
    }

    /// Add a Biscuit` to this `Authorizer`
    pub fn add_token(&mut self, token: &PyBiscuit) -> PyResult<()> {
        self.0
            .add_token(&token.0)
            .map_err(|e| BiscuitValidationError::new_err(e.to_string()))
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

    /// Query the authorizer by returning all the `Fact`s generated by the provided `Rule`. The generated facts won't be
    /// added to the authorizer world.
    ///
    /// This function can be called before `authorize`, but in that case will only return facts that are directly defined,
    /// not the facts generated by rules.
    pub fn query(&mut self, rule: &PyRule) -> PyResult<Vec<PyFact>> {
        let results = self
            .0
            .query(rule.0.clone())
            .map_err(|error| AuthorizationError::new_err(error.to_string()))?;

        Ok(results
            .iter()
            .map(|f: &builder::Fact| PyFact(f.clone()))
            .collect())
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// Builder class allowing to create a block meant to be appended to an existing token
#[pyclass(name = "BlockBuilder")]
#[derive(Clone)]
pub struct PyBlockBuilder(builder::BlockBuilder);

#[pymethods]
impl PyBlockBuilder {
    #[new]
    fn new(
        source: Option<String>,
        parameters: Option<HashMap<String, PyTerm>>,
        scope_parameters: Option<HashMap<String, PyPublicKey>>,
    ) -> PyResult<PyBlockBuilder> {
        let mut builder = PyBlockBuilder(builder::BlockBuilder::new());
        if let Some(source) = source {
            builder.add_code_with_parameters(
                &source,
                parameters.unwrap_or_default(),
                scope_parameters.unwrap_or_default(),
            )?;
        }
        Ok(builder)
    }

    /// Add a single fact to the builder. A single fact can be built with
    /// the `Fact` class and its constructor
    pub fn add_fact(&mut self, fact: &PyFact) -> PyResult<()> {
        self.0
            .add_fact(fact.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single rule to the builder. A single rule can be built with
    /// the `Rule` class and its constructor
    pub fn add_rule(&mut self, rule: &PyRule) -> PyResult<()> {
        self.0
            .add_rule(rule.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Add a single check to the builder. A single check can be built with
    /// the `Check` class and its constructor
    pub fn add_check(&mut self, check: &PyCheck) -> PyResult<()> {
        self.0
            .add_check(check.0.clone())
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    /// Merge a `BlockBuilder` in this `BlockBuilder`. The `BlockBuilder` will not be modified
    pub fn merge(&mut self, builder: &PyBlockBuilder) {
        self.0.merge(builder.0.clone())
    }

    /// Add code to the builder, using the provided parameters.
    pub fn add_code_with_parameters(
        &mut self,
        source: &str,
        raw_parameters: HashMap<String, PyTerm>,
        scope_parameters: HashMap<String, PyPublicKey>,
    ) -> PyResult<()> {
        let mut parameters = HashMap::new();

        for (k, raw_value) in raw_parameters {
            parameters.insert(k, raw_value.to_term()?);
        }

        let scope_parameters = scope_parameters
            .iter()
            .map(|(k, v)| (k.to_string(), v.0))
            .collect();

        self.0
            .add_code_with_params(source, parameters, scope_parameters)
            .map_err(|e| DataLogError::new_err(e.to_string()))
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// ed25519 keypair
#[pyclass(name = "KeyPair")]
pub struct PyKeyPair(KeyPair);

#[pymethods]
impl PyKeyPair {
    /// Generate a random keypair
    #[new]
    pub fn new() -> Self {
        PyKeyPair(KeyPair::new())
    }

    /// Generate a keypair from a private key
    #[classmethod]
    pub fn from_private_key(_: &PyType, private_key: PyPrivateKey) -> Self {
        PyKeyPair(KeyPair::from(&private_key.0))
    }

    /// The public key part
    #[getter]
    pub fn public_key(&self) -> PyPublicKey {
        PyPublicKey(self.0.public())
    }

    /// The private key part
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

/// ed25519 public key
#[derive(Clone)]
#[pyclass(name = "PublicKey")]
pub struct PyPublicKey(PublicKey);

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
        match PublicKey::from_bytes(data) {
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
        match PublicKey::from_bytes(&data) {
            Ok(key) => Ok(PyPublicKey(key)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }
}

#[pyclass(name = "PrivateKey")]
#[derive(Clone)]
/// ed25519 private key
pub struct PyPrivateKey(PrivateKey);

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
        match PrivateKey::from_bytes(data) {
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
        match PrivateKey::from_bytes(&data) {
            Ok(key) => Ok(PyPrivateKey(key)),
            Err(error) => Err(PyValueError::new_err(error.to_string())),
        }
    }
}

/// Datalog term that can occur in a set
#[derive(PartialEq, Eq, PartialOrd, Ord, FromPyObject)]
pub enum NestedPyTerm {
    Bool(bool),
    Integer(i64),
    Str(String),
    Date(PyDate),
    Bytes(Vec<u8>),
}

fn inner_term_to_py(t: &builder::Term, py: Python<'_>) -> PyResult<Py<PyAny>> {
    match t {
        builder::Term::Integer(i) => Ok((*i).into_py(py)),
        builder::Term::Str(s) => Ok(s.into_py(py)),
        builder::Term::Date(d) => Ok(Utc.timestamp_opt(*d as i64, 0).unwrap().into_py(py)),
        builder::Term::Bytes(bs) => Ok(bs.clone().into_py(py)),
        builder::Term::Bool(b) => Ok(b.into_py(py)),
        _ => Err(DataLogError::new_err("Invalid term value".to_string())),
    }
}

/// Wrapper for a non-naïve python date
#[derive(FromPyObject)]
pub struct PyDate(Py<PyDateTime>);

impl PartialEq for PyDate {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_string() == other.0.to_string()
    }
}

impl Eq for PyDate {}

impl PartialOrd for PyDate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.to_string().partial_cmp(&other.0.to_string())
    }
}

impl Ord for PyDate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}

/// Term values passed from python-land.
#[derive(FromPyObject)]
pub enum PyTerm {
    Simple(NestedPyTerm),
    Set(BTreeSet<NestedPyTerm>),
}

impl NestedPyTerm {
    pub fn to_term(&self) -> PyResult<builder::Term> {
        match self {
            NestedPyTerm::Integer(i) => Ok((*i).into()),
            NestedPyTerm::Str(s) => Ok(builder::Term::Str(s.to_string())),
            NestedPyTerm::Bytes(b) => Ok(b.clone().into()),
            NestedPyTerm::Bool(b) => Ok((*b).into()),
            NestedPyTerm::Date(PyDate(d)) => Python::with_gil(|py| {
                let ts = d.extract::<DateTime<Utc>>(py)?.timestamp();
                if ts < 0 {
                    return Err(PyValueError::new_err(
                        "Only positive timestamps are available".to_string(),
                    ));
                }
                Ok(builder::Term::Date(ts as u64))
            }),
        }
    }
}

impl PyTerm {
    pub fn to_term(&self) -> PyResult<builder::Term> {
        match self {
            PyTerm::Simple(s) => s.to_term(),
            PyTerm::Set(vs) => vs
                .iter()
                .map(|s| s.to_term())
                .collect::<PyResult<_>>()
                .map(builder::Term::Set),
        }
    }
}

/// Datalog Fact
#[pyclass(name = "Fact")]
pub struct PyFact(builder::Fact);

#[pymethods]
impl PyFact {
    /// Build a datalog fact from the provided source and optional parameter values
    #[new]
    pub fn new(source: &str, parameters: Option<HashMap<String, PyTerm>>) -> PyResult<Self> {
        let mut fact: builder::Fact = source
            .try_into()
            .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
        if let Some(parameters) = parameters {
            for (k, v) in parameters {
                fact.set(&k, v.to_term()?)
                    .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
            }
        }
        Ok(PyFact(fact))
    }

    /// The fact name
    #[getter]
    pub fn name(&self) -> String {
        self.0.predicate.name.clone()
    }

    /// The fact terms
    #[getter]
    pub fn terms(&self) -> PyResult<Vec<PyObject>> {
        self.0
            .predicate
            .terms
            .iter()
            .map(|t| {
                Python::with_gil(|py| match t {
                    builder::Term::Parameter(_) => {
                        Err(DataLogError::new_err("Invalid term value".to_string()))
                    }
                    builder::Term::Variable(_) => {
                        Err(DataLogError::new_err("Invalid term value".to_string()))
                    }
                    builder::Term::Set(_vs) => todo!(),
                    term => inner_term_to_py(term, py),
                })
            })
            .collect()
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// A single datalog rule
#[pyclass(name = "Rule")]
pub struct PyRule(builder::Rule);

#[pymethods]
impl PyRule {
    /// Build a rule from the source and optional parameter values
    #[new]
    pub fn new(
        source: &str,
        parameters: Option<HashMap<String, PyTerm>>,
        scope_parameters: Option<HashMap<String, PyPublicKey>>,
    ) -> PyResult<Self> {
        let mut rule: builder::Rule = source
            .try_into()
            .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
        if let Some(parameters) = parameters {
            for (k, v) in parameters {
                rule.set(&k, v.to_term()?)
                    .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
            }
        }

        if let Some(scope_parameters) = scope_parameters {
            for (k, v) in scope_parameters {
                rule.set_scope(&k, v.0)
                    .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
            }
        }
        Ok(PyRule(rule))
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// A single datalog check
#[pyclass(name = "Check")]
pub struct PyCheck(builder::Check);

#[pymethods]
impl PyCheck {
    /// Build a check from the source and optional parameter values
    #[new]
    pub fn new(source: &str, parameters: Option<HashMap<String, PyTerm>>) -> PyResult<Self> {
        let mut check: builder::Check = source
            .try_into()
            .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
        if let Some(parameters) = parameters {
            for (k, v) in parameters {
                check
                    .set(&k, v.to_term()?)
                    .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
            }
        }
        Ok(PyCheck(check))
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// A single datalog policy
#[pyclass(name = "Policy")]
pub struct PyPolicy(builder::Policy);

#[pymethods]
impl PyPolicy {
    /// Build a check from the source and optional parameter values
    #[new]
    pub fn new(source: &str, parameters: Option<HashMap<String, PyTerm>>) -> PyResult<Self> {
        let mut policy: builder::Policy = source
            .try_into()
            .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
        if let Some(parameters) = parameters {
            for (k, v) in parameters {
                policy
                    .set(&k, v.to_term()?)
                    .map_err(|e: error::Token| DataLogError::new_err(e.to_string()))?;
            }
        }
        Ok(PyPolicy(policy))
    }

    fn __repr__(&self) -> String {
        self.0.to_string()
    }
}

/// Main module for the biscuit_auth lib
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
