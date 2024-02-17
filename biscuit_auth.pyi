"""
Type stubs for lib.rs
"""

from __future__ import annotations
from typing import Callable, Optional, Mapping, Any, List, Union, TypeAlias

class DataLogError(Exception):
    pass

class AuthorizationError(Exception):
    pass

class BiscuitBuildError(Exception):
    pass

class BiscuitValidationError(Exception):
    pass

class BiscuitSerializationError(Exception):
    pass

class BiscuitBlockError(Exception):
    pass

Term: TypeAlias = Any
Parameters: TypeAlias = Optional[Mapping[str, Term]]
ScopeParameters: TypeAlias = Optional[Mapping[str, PublicKey]]
PrivateKeyProvider: TypeAlias = Union[
    Callable[[], PrivateKey], Callable[[int], PrivateKey]
]
PublicKeyProvider: TypeAlias = Union[
    Callable[[], PublicKey], Callable[[int], PublicKey]
]

class BiscuitBuilder:
    # Create a builder from a datalog snippet and optional parameter values
    #
    # :param source: a datalog snippet
    # :type source: str, optional
    # :param parameters: values for the parameters in the datalog snippet
    # :type parameters: dict, optional
    # :param scope_parameters: public keys for the public key parameters in the datalog snippet
    # :type scope_parameters: dict, optional
    def __new__(
        cls,
        source: Optional[str] = None,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> BiscuitBuilder: ...

    # Build a biscuit token, using the provided private key to sign the authority block
    #
    # :param root: a keypair that will be used to sign the authority block
    # :type root: PrivateKey
    # :return: a biscuit token
    # :rtype: Biscuit
    def build(self, root: PrivateKey | PrivateKeyProvider) -> Biscuit: ...

    # Add code to the builder, using the provided parameters.
    #
    # :param source: a datalog snippet
    # :type source: str, optional
    # :param parameters: values for the parameters in the datalog snippet
    # :type parameters: dict, optional
    # :param scope_parameters: public keys for the public key parameters in the datalog snippet
    # :type scope_parameters: dict, optional
    def add_code(
        self,
        source: Optional[str] = None,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> None: ...

    # Add a single fact to the builder. A single fact can be built with
    # the `Fact` class and its constructor
    #
    # :param fact: a datalog fact
    # :type fact: Fact
    def add_fact(self, fact: Fact) -> None: ...

    # Add a single rule to the builder. A single rule can be built with
    # the `Rule` class and its constructor
    #
    # :param rule: a datalog rule
    # :type rule: Rule
    def add_rule(self, rule: Rule) -> None: ...

    # Add a single check to the builder. A single check can be built with
    # the `Check` class and its constructor
    #
    # :param check: a datalog check
    # :type check: Check
    def add_check(self, check: Check) -> None: ...

    # Merge a `BlockBuilder` in this `BiscuitBuilder`. The `BlockBuilder` parameter will not be modified
    #
    # :param builder: a datalog BlockBuilder
    # :type builder: BlockBuilder
    def merge(self, builder: BlockBuilder) -> None: ...

    # Set the root key identifier for this `BiscuitBuilder`
    #
    # :param root_key_id: the root key identifier
    # :type root_key_id: int
    def set_root_key_id(self, root_key_id: int) -> None: ...

class Biscuit:
    # Creates a BiscuitBuilder
    #
    # :return: an empty BiscuitBuilder
    # :rtype: BiscuitBuilder
    @staticmethod
    def builder() -> BiscuitBuilder: ...

    # Deserializes a token from raw data
    #
    # This will check the signature using the provided root key (or function)
    #
    # :param data: raw biscuit bytes
    # :type data: bytes
    # :param root: either a public key or a function taking an integer (or `None`) and returning an public key
    # :type root: function,PublicKey
    # :return: the parsed and verified biscuit
    # :rtype: Biscuit
    @classmethod
    def from_bytes(
        cls, data: bytes, root: PublicKey | PublicKeyProvider
    ) -> Biscuit: ...

    # Deserializes a token from URL safe base 64 data
    #
    # This will check the signature using the provided root key (or function)
    #
    # :param data: a (url-safe) base64-encoded string
    # :type data: str
    # :param root: either a public key or a function taking an integer (or `None`) and returning an public key
    # :type root: function,PublicKey
    # :return: the parsed and verified biscuit
    # :rtype: Biscuit
    @classmethod
    def from_base64(cls, data: str, root: PublicKey | PublicKeyProvider) -> Biscuit: ...

    # Serializes to raw bytes
    #
    # :return: the serialized biscuit
    # :rtype: list
    def to_bytes(self) -> List[int]: ...

    # Serializes to URL safe base 64 data
    #
    # :return: the serialized biscuit
    # :rtype: str
    def to_base64(self) -> str: ...

    # Returns the number of blocks in the token
    #
    # :return: the number of blocks
    # :rtype: int
    def block_count(self) -> int: ...

    # Prints a block's content as Datalog code
    #
    # :param index: the block index
    # :type index: int
    # :return: the code for the corresponding block
    # :rtype: str
    def block_source(self, index: int) -> str: ...

    # Create a new `Biscuit` by appending an attenuation block
    #
    # :param block: a builder for the new block
    # :type block: BlockBuilder
    # :return: the attenuated biscuit
    # :rtype: Biscuit
    def append(self, block: BlockBuilder) -> Biscuit: ...

    # The revocation ids of the token, encoded as hexadecimal strings
    @property
    def revocation_ids(self) -> List[str]: ...

class Authorizer:
    # Create a new authorizer from a datalog snippet and optional parameter values
    #
    # :param source: a datalog snippet
    # :type source: str, optional
    # :param parameters: values for the parameters in the datalog snippet
    # :type parameters: dict, optional
    # :param scope_parameters: public keys for the public key parameters in the datalog snippet
    # :type scope_parameters: dict, optional
    def __new__(
        cls,
        source: Optional[str] = None,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> Authorizer: ...

    # Add code to the builder, using the provided parameters.
    #
    # :param source: a datalog snippet
    # :type source: str, optional
    # :param parameters: values for the parameters in the datalog snippet
    # :type parameters: dict, optional
    # :param scope_parameters: public keys for the public key parameters in the datalog snippet
    # :type scope_parameters: dict, optional
    def add_code(
        self,
        source: Optional[str] = None,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> None: ...

    # Add a single fact to the authorizer. A single fact can be built with
    # the `Fact` class and its constructor
    #
    # :param fact: a datalog fact
    # :type fact: Fact
    def add_fact(self, fact: Fact) -> None: ...

    # Add a single rule to the authorizer. A single rule can be built with
    # the `Rule` class and its constructor
    #
    # :param rule: a datalog rule
    # :type rule: Rule
    def add_rule(self, rule: Rule) -> None: ...

    # Add a single check to the authorizer. A single check can be built with
    # the `Check` class and its constructor
    #
    # :param check: a datalog check
    # :type check: Check
    def add_check(self, check: Check) -> None: ...

    # Add a single policy to the authorizer. A single policy can be built with
    # the `Policy` class and its constructor
    #
    # :param policy: a datalog policy
    # :type policy: Policy
    def add_policy(self, policy: Policy) -> None: ...

    # Merge another `Authorizer` in this `Authorizer`. The `Authorizer` argument will not be modified
    #
    # :param builder: an Authorizer
    # :type builder: Authorizer
    def merge(self, builder: Authorizer) -> None: ...

    # Merge a `BlockBuilder` in this `Authorizer`. The `BlockBuilder` will not be modified
    #
    # :param builder: a BlockBuilder
    # :type builder: BlockBuilder
    def merge_block(self, builder: BlockBuilder) -> None: ...

    # Add a `Biscuit` to this `Authorizer`
    #
    # :param token: the token to authorize
    # :type token: Biscuit
    def add_token(self, token: Biscuit) -> None: ...

    # Runs the authorization checks and policies
    #
    # Returns the index of the matching allow policy, or an error containing the matching deny
    # policy or a list of the failing checks
    #
    # :return: the index of the matched allow rule
    # :rtype: int
    def authorize(self) -> int: ...

    # Query the authorizer by returning all the `Fact`s generated by the provided `Rule`. The generated facts won't be
    # added to the authorizer world.
    #
    # This function can be called before `authorize`, but in that case will only return facts that are directly defined,
    # not the facts generated by rules.
    #
    # :param rule: a rule that will be ran against the authorizer contents
    # :type rule: Rule
    # :return: a list of generated facts
    # :rtype: list
    def query(self, rule: Rule) -> List[Fact]: ...

    # Take a snapshot of the authorizer and return it, base64-encoded
    #
    # :return: a snapshot as a base64-encoded string
    # :rtype: str
    def base64_snapshot(self) -> str: ...

    # Take a snapshot of the authorizer and return it, as raw bytes
    #
    # :return: a snapshot as raw bytes
    # :rtype: bytes
    def raw_snapshot(self) -> bytes: ...

    # Build an authorizer from a base64-encoded snapshot
    #
    # :param input: base64-encoded snapshot
    # :type input: str
    # :return: the authorizer
    # :rtype: Authorizer
    @classmethod
    def from_base64_snapshot(cls, input: str) -> Authorizer: ...

    # Build an authorizer from a snapshot's raw bytes
    #
    # :param input: raw snapshot bytes
    # :type input: bytes
    # :return: the authorizer
    # :rtype: Authorizer
    @classmethod
    def from_raw_snapshot(cls, input: bytes) -> Authorizer: ...

# Builder class allowing to create a block meant to be appended to an existing token
class BlockBuilder:
    def __new__(
        cls,
        source: Optional[str],
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> BlockBuilder: ...

    # Add a single fact to the builder. A single fact can be built with
    # the `Fact` class and its constructor
    #
    # :param fact: a datalog fact
    # :type fact: Fact
    def add_fact(self, fact: Fact) -> None: ...

    # Add a single rule to the builder. A single rule can be built with
    # the `Rule` class and its constructor
    #
    # :param rule: a datalog rule
    # :type rule: Rule
    def add_rule(self, rule: Rule) -> None: ...

    # Add a single check to the builder. A single check can be built with
    # the `Check` class and its constructor
    #
    # :param check: a datalog check
    # :type check: Check
    def add_check(self, check: Check) -> None: ...

    # Merge a `BlockBuilder` in this `BlockBuilder`. The `BlockBuilder` will not be modified
    #
    # :param builder: a datalog BlockBuilder
    # :type builder: BlockBuilder
    def merge(self, builder: BlockBuilder) -> None: ...

    # Add code to the builder, using the provided parameters.
    #
    # :param source: a datalog snippet
    # :type source: str, optional
    # :param parameters: values for the parameters in the datalog snippet
    # :type parameters: dict, optional
    # :param scope_parameters: public keys for the public key parameters in the datalog snippet
    # :type scope_parameters: dict, optional
    def add_code(
        self,
        source: Optional[str],
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> None: ...

# ed25519 keypair
class KeyPair:
    # Generate a random keypair
    def __new__(cls) -> KeyPair: ...

    # Generate a keypair from a private key
    #
    # :param private_key: the private key
    # :type private_key: PrivateKey
    # :return: the corresponding keypair
    # :rtype: KeyPair
    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> KeyPair: ...

    # Generate a keypair from a DER buffer
    #
    # :param bytes: private key bytes in DER format
    # :type private_key: PrivateKey
    # :return: the corresponding keypair
    # :rtype: KeyPair
    @classmethod
    def from_private_key_der(cls, der: bytes) -> KeyPair: ...

    #
    # :param bytes: private key bytes in PEM format
    # :type private_key: PrivateKey
    # :return: the corresponding keypair
    # :rtype: KeyPair
    @classmethod
    def from_private_key_pem(cls, pem: str) -> KeyPair: ...

    # The public key part
    @property
    def public_key(self) -> PublicKey: ...

    # The private key part
    @property
    def private_key(self) -> PrivateKey: ...

# ed25519 public key
class PublicKey:
    # Serializes a public key to raw bytes
    #
    # :return: the public key bytes
    # :rtype: list
    def to_bytes(self) -> bytes: ...

    # Serializes a public key to a hexadecimal string
    #
    # :return: the public key bytes (hex-encoded)
    # :rtype: str
    def to_hex(self) -> str: ...

    # Deserializes a public key from raw bytes
    #
    # :param data: the raw bytes
    # :type data: bytes
    # :return: the public key
    # :rtype: PublicKey
    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey: ...

    # Deserializes a public key from a hexadecimal string
    #
    # :param data: the hex-encoded string
    # :type data: str
    # :return: the public key
    # :rtype: PublicKey
    @classmethod
    def from_hex(cls, data: str) -> PublicKey: ...

# ed25519 private key
class PrivateKey:
    # Serializes a public key to raw bytes
    #
    # :return: the public key bytes
    # :rtype: list
    def to_bytes(self) -> bytes: ...

    # Serializes a private key to a hexadecimal string
    #
    # :return: the private key bytes (hex-encoded)
    # :rtype: str
    def to_hex(self) -> str: ...

    # Deserializes a private key from raw bytes
    #
    # :param data: the raw bytes
    # :type data: bytes
    # :return: the private key
    # :rtype: PrivateKey
    @classmethod
    def from_bytes(cls, data: bytes) -> PrivateKey: ...

    # Deserializes a private key from a hexadecimal string
    #
    # :param data: the hex-encoded string
    # :type data: str
    # :return: the private key
    # :rtype: PrivateKey
    @classmethod
    def from_hex(cls, data: str) -> PrivateKey: ...

# A single datalog Fact
#
# :param source: a datalog fact (without the ending semicolon)
# :type source: str
# :param parameters: values for the parameters in the datalog fact
# :type parameters: dict, optional
class Fact:
    # Build a datalog fact from the provided source and optional parameter values
    def __new__(cls, source: str, parameters: Parameters = None) -> Fact: ...

    # The fact name
    @property
    def name(self) -> str: ...

    # The fact terms
    @property
    def terms(self) -> List[Any]: ...

# A single datalog rule
#
# :param source: a datalog rule (without the ending semicolon)
# :type source: str
# :param parameters: values for the parameters in the datalog rule
# :type parameters: dict, optional
# :param scope_parameters: public keys for the public key parameters in the datalog rule
# :type scope_parameters: dict, optional
class Rule:
    # Build a rule from the source and optional parameter values
    def __new__(
        cls,
        source: str,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> Rule: ...

# A single datalog check
#
# :param source: a datalog check (without the ending semicolon)
# :type source: str
# :param parameters: values for the parameters in the datalog check
# :type parameters: dict, optional
# :param scope_parameters: public keys for the public key parameters in the datalog check
# :type scope_parameters: dict, optional
class Check:
    # Build a check from the source and optional parameter values
    def __new__(
        cls,
        source: str,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> Check: ...

# A single datalog policy
#
# :param source: a datalog policy (without the ending semicolon)
# :type source: str
# :param parameters: values for the parameters in the datalog policy
# :type parameters: dict, optional
# :param scope_parameters: public keys for the public key parameters in the datalog policy
# :type scope_parameters: dict, optional
class Policy:
    # Build a check from the source and optional parameter values
    def __new__(
        cls,
        source: str,
        parameters: Parameters = None,
        scope_parameters: ScopeParameters = None,
    ) -> Policy: ...

# Representation of a biscuit token that has been parsed but not cryptographically verified
class UnverifiedBiscuit:
    # Deserializes a token from URL safe base 64 data
    #
    # The signature will NOT be checked
    #
    # :param data: a (url-safe) base64-encoded string
    # :type data: str
    # :return: the parsed, unverified biscuit
    # :rtype: UnverifiedBiscuit
    @classmethod
    def from_base64(cls, data: str) -> UnverifiedBiscuit: ...

    # Returns the root key identifier for this `UnverifiedBiscuit` (or `None` if there is none)
    #
    # :return: the root key identifier
    # :rtype: int
    def root_key_id(self) -> Optional[int]: ...

    # Returns the number of blocks in the token
    #
    # :return: the number of blocks
    # :rtype: int
    def block_count(self) -> int: ...

    # Prints a block's content as Datalog code
    #
    # :param index: the block index
    # :type index: int
    # :return: the code for the corresponding block
    # :rtype: str
    def block_source(self, index: int) -> str: ...

    # Create a new `UnverifiedBiscuit` by appending an attenuation block
    #
    # :param block: a builder for the new block
    # :type block: BlockBuilder
    # :return: the attenuated biscuit
    # :rtype: Biscuit
    def append(self, block: BlockBuilder) -> UnverifiedBiscuit: ...

    # The revocation ids of the token, encoded as hexadecimal strings
    @property
    def revocation_ids(self) -> List[str]: ...
    def verify(self, root: PublicKey) -> Biscuit: ...
