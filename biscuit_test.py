import pytest
import biscuit_auth

VALID_HEX_KEYPAIR = {
    "public": "e6fe4661710cfc3b7a259258a2505ebf8ca5e543adcc944c23470e4e5e6585e8",
    "private": "39595423ef9c4f359223fba7b30112435d9f446f57f6a53c36d79026cc0331c2"
}


'''
Here's a valid Base64 encoded Biscuit, with the following attributes:
Biscuit {
    symbols: ["authority", "ambient", "resource", "operation", "right", "current_time", "revocation_id", "/a/file1.txt", "read", "write", "/a/file2.txt", "/a/file3.txt"]
    authority: Block {
            symbols: ["/a/file1.txt", "read", "write", "/a/file2.txt", "/a/file3.txt"]
            version: 2
            context: ""
            facts: [
                right("/a/file1.txt", "read"),
                right("/a/file1.txt", "write"),
                right("/a/file2.txt", "read"),
                right("/a/file3.txt", "write")
            ]
            rules: []
            checks: []
        }
    blocks: [

    ]
}
'''
VALID_TOKEN_BASE64 = "EtsBCnEKDC9hL2ZpbGUxLnR4dAoEcmVhZAoFd3JpdGUKDC9hL2ZpbGUyLnR4dAoML2EvZmlsZTMudHh0GAIiDAoKCAQSAhgHEgIYCCIMCgoIBBICGAcSAhgJIgwKCggEEgIYChICGAgiDAoKCAQSAhgLEgIYCRIkCAASIHx15tkXJCiAWinyuBMn-Vf5qYQl4by9ZP_9yBe0wDyTGkDhgkDt8XwW0yIj_xbtE2fwYVrq0LM8PITiQx7jnVl8OwKyWQiUCSy8uqdWv_XqQaBzVDf2hK7857TqHTqE8zEFIiIKIGjlwhdfjrob0rFWOkCmxBxMeiyc5VkxALSgQKVGcJiV"

def test_keys():
    public_key_from_hex = biscuit_auth.PublicKey.from_hex(VALID_HEX_KEYPAIR["public"])
    public_key_bytes = bytes(public_key_from_hex.to_bytes())
    public_key_from_bytes = biscuit_auth.PublicKey.from_bytes(public_key_bytes)
    assert public_key_from_bytes.to_hex() == VALID_HEX_KEYPAIR["public"]

def test_biscuit_builder():
    kp = biscuit_auth.KeyPair()
    builder = biscuit_auth.BiscuitBuilder()
    builder.add_authority_fact('right("/a/file1.txt", "read")')
    builder.add_authority_fact('right("/a/file1.txt", "write")')
    builder.add_authority_fact('right("/a/file2.txt", "read")')
    builder.add_authority_fact('right("/a/file3.txt", "write")')
    token = builder.build(kp)

    assert len(token.to_bytes()) == 258


def test_authorizer():
    kp = biscuit_auth.KeyPair()
    builder = biscuit_auth.BiscuitBuilder()
    builder.add_authority_fact('right("/a/file1.txt", "read")')
    builder.add_authority_fact('right("/a/file1.txt", "write")')
    builder.add_authority_fact('right("/a/file2.txt", "read")')
    builder.add_authority_fact('right("/a/file3.txt", "write")')
    token = builder.build(kp)

    authorizer = token.authorizer()

    authorizer.add_fact('resource("/a/file1.txt")')
    authorizer.add_fact('operation("write")')
    authorizer.add_policy('allow if right("/a/file1.txt", "read")')
    authorizer.add_policy("deny if true")
    authorizer.authorize()

    authorizer2 = token.authorizer()
    authorizer2.add_fact('resource("/a/file4.txt")')
    authorizer2.add_fact('operation("write")')
    authorizer2.add_policy('allow if right("/a/file4.txt", "write")')
    authorizer2.add_policy("deny if true")
    with pytest.raises(biscuit_auth.AuthorizationError):
        authorizer2.authorize()



