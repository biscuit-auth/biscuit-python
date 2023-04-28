import json
import os
from datetime import datetime, timezone

import pytest

from biscuit_auth import Authorizer, Biscuit, BiscuitBuilder, BlockBuilder, Check, Fact, KeyPair, Policy, PrivateKey, PublicKey, Rule

def test_biscuit_builder():
    kp = KeyPair()

    builder = BiscuitBuilder(
      """
        string({str});
        int({int});
        bool({bool});
        bytes({bytes});
        datetime({datetime});
        check if true trusting {pubkey};
      """,
      { 'str': "1234",
        'int': 1,
        'bool': True,
        'bytes': [0xaa, 0xbb],
        'datetime': datetime(2023, 4, 3, 10, 0, 0, tzinfo = timezone.utc),
      },
      { 'pubkey': PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189") }
    )

    builder.add_fact(Fact("fact(false)"));
    builder.add_fact(Fact("fact({f})", { 'f': True }));
    builder.add_rule(Rule("head($var) <- fact($var, {f})", { 'f': True }));
    builder.add_rule(Rule(
        "head($var) <- fact($var, {f}) trusting {pubkey}",
        { 'f': True },
        { 'pubkey': PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189") }
    ));
    builder.add_check(Check("check if fact($var, {f})", { 'f': True }));
    builder.merge(BlockBuilder('builder(true);'))

    assert repr(builder) == """// no root key id set
string("1234");
int(1);
bool(true);
bytes(hex:aabb);
datetime(2023-04-03T10:00:00Z);
fact(false);
fact(true);
builder(true);
head($var) <- fact($var, true);
head($var) <- fact($var, true) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
check if true trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
check if fact($var, true);
"""

    builder.build(kp.private_key)
    assert True

def test_block_builder():
    builder = BlockBuilder(
      """
        string({str});
        int({int});
        bool({bool});
        bytes({bytes});
        datetime({datetime});
        check if true trusting {pubkey};
      """,
      { 'str': "1234",
        'int': 1,
        'bool': True,
        'bytes': [0xaa, 0xbb],
        'datetime': datetime(2023, 4, 3, 10, 0, 0, tzinfo = timezone.utc),
      },
      { 'pubkey': PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189") }
    )

    builder.add_fact(Fact("fact(false)"));
    builder.add_fact(Fact("fact({f})", { 'f': True }));
    builder.add_rule(Rule("head($var) <- fact($var, {f})", { 'f': True }));
    builder.add_rule(Rule(
        "head($var) <- fact($var, {f}) trusting {pubkey}",
        { 'f': True },
        { 'pubkey': PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189") }
    ));
    builder.add_check(Check("check if fact($var, {f})", { 'f': True }));
    builder.merge(BlockBuilder('builder(true);'))

    assert repr(builder) == """string("1234");
int(1);
bool(true);
bytes(hex:aabb);
datetime(2023-04-03T10:00:00Z);
fact(false);
fact(true);
builder(true);
head($var) <- fact($var, true);
head($var) <- fact($var, true) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
check if true trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
check if fact($var, true);
"""

def test_authorizer_builder():
    builder = Authorizer(
      """
        string({str});
        int({int});
        bool({bool});
        bytes({bytes});
        datetime({datetime});
        check if true trusting {pubkey};
        allow if true;
      """,
      { 'str': "1234",
        'int': 1,
        'bool': True,
        'bytes': [0xaa, 0xbb],
        'datetime': datetime(2023, 4, 3, 10, 0, 0, tzinfo = timezone.utc),
      },
      { 'pubkey': PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189") }
    )

    builder.add_fact(Fact("fact(false)"));
    builder.add_fact(Fact("fact({f})", { 'f': True }));
    builder.add_rule(Rule("head($var) <- fact($var, {f})", { 'f': True }));
    builder.add_rule(Rule(
        "head($var) <- fact($var, {f}) trusting {pubkey}",
        { 'f': True },
        { 'pubkey': PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189") }
    ));
    builder.add_check(Check("check if fact($var, {f})", { 'f': True }));
    builder.merge_block(BlockBuilder('builder(true);'))
    builder.merge(Authorizer('builder(false);'))

    try:
        builder.authorize()
    except:
        pass

    assert repr(builder) == """// Facts:
// origin: authorizer
bool(true);
builder(false);
builder(true);
bytes(hex:aabb);
datetime(2023-04-03T10:00:00Z);
fact(false);
fact(true);
int(1);
string("1234");

// Rules:
// origin: authorizer
head($var) <- fact($var, true);
head($var) <- fact($var, true) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;

// Checks:
// origin: authorizer
check if true trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;
check if fact($var, true);

// Policies:
allow if true;
"""

def test_complete_lifecycle():
    private_key = PrivateKey.from_hex("473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97")
    root = KeyPair.from_private_key(private_key)

    biscuit_builder = BiscuitBuilder("user({id})", { 'id': "1234" })

    for right in ["read", "write"]:
        biscuit_builder.add_fact(Fact("fact({right})", { 'right': right}))

    token = biscuit_builder.build(private_key).append(BlockBuilder('check if user($u)')).to_base64()

    parsedToken = Biscuit.from_base64(token, root.public_key)

    authorizer = Authorizer("allow if user({id})", { 'id': "1234" })

    print(authorizer)
    authorizer.add_token(parsedToken)

    policy = authorizer.authorize()

    assert policy == 0

    rule = Rule("u($id) <- user($id), $id == {id}", { 'id': "1234"})
    facts = authorizer.query(rule)

    assert repr(facts) == repr([Fact('u("1234")')])

def test_public_keys():
    # Happy path (hex to bytes and back)
    public_key_from_hex = PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189")
    public_key_bytes = bytes(public_key_from_hex.to_bytes())
    public_key_from_bytes = PublicKey.from_bytes(public_key_bytes)
    assert public_key_from_bytes.to_hex() == "acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

    # Not valid hex
    with pytest.raises(ValueError):
        PublicKey.from_hex("notarealkey")

    # Valid hex, but too short
    with pytest.raises(ValueError):
        PublicKey.from_hex("deadbeef1234")

    # Not enough bytes
    with pytest.raises(ValueError):
        PublicKey.from_bytes(b"1230fw9ia3")

def test_private_keys():
    # Happy path (hex to bytes and back)
    private_key_from_hex = PrivateKey.from_hex("12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a")
    private_key_bytes = bytes(private_key_from_hex.to_bytes())
    private_key_from_bytes = PrivateKey.from_bytes(private_key_bytes)
    assert private_key_from_bytes.to_hex() == "12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a"

    # Not valid hex
    with pytest.raises(ValueError):
        PrivateKey.from_hex("notarealkey")

    # Valid hex, but too short
    with pytest.raises(ValueError):
        PrivateKey.from_hex("deadbeef1234")

    # Not enough bytes
    with pytest.raises(ValueError):
        PrivateKey.from_bytes(b"1230fw9ia3")
