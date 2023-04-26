import json
import os

import pytest

import biscuit_auth

def test_biscuit_builder():
    kp = biscuit_auth.KeyPair()

    builder = biscuit_auth.BiscuitBuilder()
    # todo booleans, dates, public keys in trusting annotations
    builder.add_code_with_parameters(
      """
        string({str});
        int({int});
        // bool({bool}); // todo booleans seem to be turned into numbers
        bytes({bytes});
      """,
      { 'str': "1234",
        'int': 1234,
        'bool': True,
        'bytes': [0xaa, 0xbb],
      }
    )

    builder.add_fact(biscuit_auth.Fact("fact({f})", { 'f': True }));
    builder.add_rule(biscuit_auth.Rule("head($var) <- fact($var, {f})", { 'f': True }));
    builder.add_check(biscuit_auth.Check("check if fact($var, {f})", { 'f': True }));
    new_builder = biscuit_auth.BlockBuilder()
    new_builder.add_code('builder(true);')
    builder.merge(new_builder)

    assert repr(builder) == '// no root key id set\nstring("1234");\nint(1234);\nbytes(hex:aabb);\n'

    builder.build(kp.private_key)
    assert True

def test_authorizer_builder():
    builder = biscuit_auth.Authorizer()
    # todo booleans, dates, public keys in trusting annotations
    builder.add_code_with_parameters(
      """
        string({str});
        int({int});
        // bool({bool}); // todo booleans seem to be turned into numbers
        bytes({bytes});
        allow if true;
      """,
      { 'str': "1234",
        'int': 1234,
        'bool': True,
        'bytes': [0xaa, 0xbb],
      }
    )

    builder.add_fact(biscuit_auth.Fact("fact({f})", { 'f': True }));
    builder.add_rule(biscuit_auth.Rule("head($var) <- fact($var, {f})", { 'f': True }));
    builder.add_check(biscuit_auth.Check("check if fact($var, {f})", { 'f': True }));
    new_builder = biscuit_auth.BlockBuilder()
    new_builder.add_code('builder(true);')
    builder.merge_block(new_builder)
    new_authorizer = biscuit_auth.Authorizer()
    new_authorizer.add_code('builder(true);')
    builder.merge(new_authorizer)

    # todo add fact / add rule / add check / add policy / merge / merge block

    assert repr(builder) == 'todo'

def test_public_keys():
    # Happy path (hex to bytes and back)
    public_key_from_hex = biscuit_auth.PublicKey.from_hex("acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189")
    public_key_bytes = bytes(public_key_from_hex.to_bytes())
    public_key_from_bytes = biscuit_auth.PublicKey.from_bytes(public_key_bytes)
    assert public_key_from_bytes.to_hex() == "acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189"

    # Not valid hex
    with pytest.raises(ValueError):
        biscuit_auth.PublicKey.from_hex("notarealkey")

    # Valid hex, but too short
    with pytest.raises(ValueError):
        biscuit_auth.PublicKey.from_hex("deadbeef1234")

    # Not enough bytes
    with pytest.raises(ValueError):
        biscuit_auth.PublicKey.from_bytes(b"1230fw9ia3")

def test_private_keys():
    # Happy path (hex to bytes and back)
    private_key_from_hex = biscuit_auth.PrivateKey.from_hex("12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a")
    private_key_bytes = bytes(private_key_from_hex.to_bytes())
    private_key_from_bytes = biscuit_auth.PrivateKey.from_bytes(private_key_bytes)
    assert private_key_from_bytes.to_hex() == "12aca40167fbdd1a11037e9fd440e3d510d9d9dea70a6646aa4aaf84d718d75a"

    # Not valid hex
    with pytest.raises(ValueError):
        biscuit_auth.PrivateKey.from_hex("notarealkey")

    # Valid hex, but too short
    with pytest.raises(ValueError):
        biscuit_auth.PrivateKey.from_hex("deadbeef1234")

    # Not enough bytes
    with pytest.raises(ValueError):
        biscuit_auth.PrivateKey.from_bytes(b"1230fw9ia3")
