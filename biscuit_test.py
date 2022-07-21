import json
import os

import pytest

import biscuit_auth

with open("samples/samples.json") as samples_json:
    TEST_CASES = json.load(samples_json)

def get_test_keys():
    return biscuit_auth.PrivateKey.from_hex(TEST_CASES["root_private_key"]), biscuit_auth.PublicKey.from_hex(TEST_CASES["root_public_key"])

def get_authorizer(biscuit, world: dict):
    authorizer = biscuit.authorizer()
    for fact in world["facts"]:
        authorizer.add_fact(fact)
    for rule in world["rules"]:
        authorizer.add_rule(rule)
    for check in world["checks"]:
        authorizer.add_check(check)
    for policy in world["policies"]:
        authorizer.add_policy(policy)
    return authorizer

def test_1_basic():
    test_case = TEST_CASES["testcases"][0]
    private_root, public_root = get_test_keys()

    # This example should fail to authorize
    with open(os.path.join("samples", test_case["filename"]), "rb") as biscuit_fp:
        with pytest.raises(biscuit_auth.BiscuitValidationError):
            biscuit_auth.Biscuit.from_bytes(biscuit_fp.read(), public_root)

    # Now lets make sure we can build the same token that also fails
    kp = biscuit_auth.KeyPair.from_existing(private_root)

    builder = biscuit_auth.BiscuitBuilder()
    for fact in test_case["token"][0]["code"].strip().split("\n"):
        builder.add_authority_fact(fact.strip(";"))
    token = builder.build(kp)

    new_block = token.create_block()
    new_block.add_code(test_case["token"][1]["code"])

    token = token.append(new_block)

    authorizer = get_authorizer(token, test_case["validations"][""]["world"])

    with pytest.raises(biscuit_auth.AuthorizationError):
        authorizer.authorize()

def test_2_different_root_key():
    test_case = TEST_CASES["testcases"][1]
    _, public_root = get_test_keys()

    # This example should fail to authorize
    with open(os.path.join("samples", test_case["filename"]), "rb") as biscuit_fp:
        with pytest.raises(biscuit_auth.BiscuitValidationError):
            biscuit_auth.Biscuit.from_bytes(biscuit_fp.read(), public_root)

def test_3_invalid_signature_format():
    test_case = TEST_CASES["testcases"][2]
    _, public_root = get_test_keys()

    # This example should fail to authorize
    with open(os.path.join("samples", test_case["filename"]), "rb") as biscuit_fp:
        with pytest.raises(biscuit_auth.BiscuitValidationError):
            biscuit_auth.Biscuit.from_bytes(biscuit_fp.read(), public_root)

def test_public_keys():
    # Happy path (hex to bytes and back)
    public_key_from_hex = biscuit_auth.PublicKey.from_hex(TEST_CASES["root_public_key"])
    public_key_bytes = bytes(public_key_from_hex.to_bytes())
    public_key_from_bytes = biscuit_auth.PublicKey.from_bytes(public_key_bytes)
    assert public_key_from_bytes.to_hex() == TEST_CASES["root_public_key"]

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
    private_key_from_hex = biscuit_auth.PrivateKey.from_hex(TEST_CASES["root_private_key"])
    private_key_bytes = bytes(private_key_from_hex.to_bytes())
    private_key_from_bytes = biscuit_auth.PrivateKey.from_bytes(private_key_bytes)
    assert private_key_from_bytes.to_hex() == TEST_CASES["root_private_key"]

    # Not valid hex
    with pytest.raises(ValueError):
        biscuit_auth.PrivateKey.from_hex("notarealkey")

    # Valid hex, but too short
    with pytest.raises(ValueError):
        biscuit_auth.PrivateKey.from_hex("deadbeef1234")

    # Not enough bytes
    with pytest.raises(ValueError):
        biscuit_auth.PrivateKey.from_bytes(b"1230fw9ia3")
