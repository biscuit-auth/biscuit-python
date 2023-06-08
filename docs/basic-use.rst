Basic use
=========


>>> from biscuit_auth import Authorizer, Biscuit, BiscuitBuilder, BlockBuilder, KeyPair, PrivateKey, PublicKey, Rule
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

Query an authorizer
-------------------

>>> facts = authorizer.query(Rule("user($u) <- user($u)"))
>>> len(facts)
1
>>> facts[0].name
'user'
>>> facts[0].terms
['1234']