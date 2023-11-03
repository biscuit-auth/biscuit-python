Basic use
=========


>>> from biscuit_auth import Authorizer, Biscuit, BiscuitBuilder, BlockBuilder, KeyPair, PrivateKey, PublicKey, Rule, UnverifiedBiscuit
>>> from datetime import datetime, timedelta, timezone

Create and manage keypairs
--------------------------

>>> # random keypair
>>> keypair = KeyPair()
>>> # serialize a keypair to hexadecimal strings
>>> private_key_str = keypair.private_key.to_hex()
>>> public_key_str = keypair.public_key.to_hex()
>>> # parse a private key from an hex string
>>> parsed_private_key = PrivateKey.from_hex("23d9d45b32899eefd4cde9a2caecdd41f0449c95ee1e4c6b53ef38cb957dd690")
>>> # parse a public key from an hex string
>>> parsed_public_key = PublicKey.from_hex("9e124fbb46ff99a87219aef4b09f4f6c3b7fd96b7bd279e38af3ef429a101c69")
>>> # build a keypair from a private key
>>> parsed_keypair = KeyPair.from_private_key(parsed_private_key)
>>> parsed_keypair.private_key.to_hex()
'23d9d45b32899eefd4cde9a2caecdd41f0449c95ee1e4c6b53ef38cb957dd690'
>>> parsed_keypair.public_key.to_hex()
'9e124fbb46ff99a87219aef4b09f4f6c3b7fd96b7bd279e38af3ef429a101c69'

Build a biscuit token
---------------------

>>> private_key = PrivateKey.from_hex("23d9d45b32899eefd4cde9a2caecdd41f0449c95ee1e4c6b53ef38cb957dd690")
>>> token = BiscuitBuilder("""
... user({user_id});
... check if time($time), $time < {expiration};
... """,
... {
...    'user_id': '1234',
...    'expiration': datetime.now(tz = timezone.utc) + timedelta(days = 1)
... }
... ).build(private_key)
>>> token_string = token.to_base64()

Biscuit tokens can carry a root key identifier, helping the verifying party select the correct public key amongst several valid keys. This is especially useful when performing key rotation, when multiple keys are active at the same time.

>>> private_key = PrivateKey.from_hex("00731a0f129f088e069d8a8b3523a724bc48136bfc22c916cb754adbf503ad5e")
>>> builder = BiscuitBuilder("""
... user({user_id});
... check if time($time), $time < {expiration};
... """,
... {
...    'user_id': '1234',
...    'expiration': datetime.now(tz = timezone.utc) + timedelta(days = 1)
... }
... )
>>> builder.set_root_key_id(1)
>>> token = builder.build(private_key)
>>> token_string = token.to_base64()

Each block of a token is identified by a unique revocation id. This allows revoking a token and all the tokens derived from it.

>>> revocation_ids = token.revocation_ids

Append a block to a biscuit token
---------------------------------

>>> attenuated_token = token.append(BlockBuilder("""
... check if operation("read");
... check if resource({res})
... """, { 'res': 'file1'}))

Parse and authorize a biscuit token
-----------------------------------

>>> public_key = PublicKey.from_hex("9e124fbb46ff99a87219aef4b09f4f6c3b7fd96b7bd279e38af3ef429a101c69")
>>> token = Biscuit.from_base64("En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiCp8D9laR_CXmFmiUlo6zi8L63iapXDxX1evELp4HVaBRpAx3Mkwu2f2AcNq48IZwu-pxACq1stL76DSMGEugmiduuTVwMqLmgKZ4VFgzeydCrYY_Id3MkxgTgjXzEHUH4DDSIiCiB55I7ykL9wQXHRDqUnSgZwCdYNdO7c8LZEj0VH5sy3-Q==", public_key)
>>> authorizer = Authorizer( """ time({now}); allow if user($u); """, { 'now': datetime.now(tz = timezone.utc)} )
>>> authorizer.add_token(token)
>>> authorizer.authorize()
0

In order to help with key rotation, biscuit tokens can optionally carry a root key identifier, helping the verifying party choose between several valid public keys.

>>> def public_key_fn(kid):
...   if kid is None:
...     return PublicKey.from_hex("9e124fbb46ff99a87219aef4b09f4f6c3b7fd96b7bd279e38af3ef429a101c69")
...   elif kid == 1:
...     return PublicKey.from_hex("1d211ddaf521cc45b620431817ba4fe0457be467ba4d724ecf514db3070b53cc")
...   else:
...     raise Exception("unknown key identifier")
>>> token = Biscuit.from_base64("CAESfQoTCgQxMjM0GAMiCQoHCAoSAxiACBIkCAASII5WVsvM52T91C12wnzButmyzmtGSX_rbM6hCSIJihX2GkDwAcVxTnY8aeMLm-i2R_VzTfIMQZya49ogXO2h2Fg2TJsDcG3udIki9il5PA05lKUwrfPNroS7Qg5e04AyLLcHIiIKII5rh75jrCrgE6Rzw6GVYczMn1IOo287uO4Ef5wp7obY", public_key_fn)
>>> authorizer = Authorizer( """ time({now}); allow if user($u); """, { 'now': datetime.now(tz = timezone.utc)} )
>>> authorizer.add_token(token)
>>> authorizer.authorize()
0

It is possible to parse a biscuit token without verifying its signatures,for instance to inspect its contents, extract revocation ids or append a block.

>>> utoken = UnverifiedBiscuit.from_base64("CAESfQoTCgQxMjM0GAMiCQoHCAoSAxiACBIkCAASII5WVsvM52T91C12wnzButmyzmtGSX_rbM6hCSIJihX2GkDwAcVxTnY8aeMLm-i2R_VzTfIMQZya49ogXO2h2Fg2TJsDcG3udIki9il5PA05lKUwrfPNroS7Qg5e04AyLLcHIiIKII5rh75jrCrgE6Rzw6GVYczMn1IOo287uO4Ef5wp7obY")
>>> utoken.revocation_ids
['f001c5714e763c69e30b9be8b647f5734df20c419c9ae3da205ceda1d858364c9b03706dee748922f629793c0d3994a530adf3cdae84bb420e5ed380322cb707']
>>> attenuated = utoken.append(BlockBuilder("check if true"))

An unverified token can be verified and turned into a regular token

>>> token = utoken.verify(public_key_fn)

Query an authorizer
-------------------

>>> facts = authorizer.query(Rule("user($u) <- user($u)"))
>>> len(facts)
1
>>> facts[0].name
'user'
>>> facts[0].terms
['1234']

Save and load snapshots
-----------------------

>>> snapshot = authorizer.base64_snapshot()
>>> parsed = Authorizer.from_base64_snapshot(snapshot)
