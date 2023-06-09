Working with datalog
====================

Biscuit uses a custom logic language both for token contents and authorization rules.

biscuit-python strives to make it easy to embed datalog snippets in python programs.

**Building datalog snippets through string manipulation is dangerous, do not do it**. Biscuit-python provides safe way to exchange values between python and datalog.

Parameter interpolation
-----------------------

Datalog parameters provide a way to inject dynamic values in datalog without manipulating strings directly. This avoids datalog injections, which are similar to SQL injections.

Parameters are names enclosed in curly brackets: `{param}`. They can appear everywhere a value is allowed: in predicate terms, or within expressions.

All datalog builders (`BiscuitBuilder`, `BlockBuilder`, `Authorizer`, `Fact`, `Rule`, `Check`, `Policy`) support parameters: a dictionnary containing params values must be supplied along the datalog code:

>>> from biscuit_auth import BiscuitBuilder, BlockBuilder, Authorizer, Check, Fact, Rule, Policy, PublicKey
>>> Fact("user({user})", { 'user': 1234})
user(1234)
>>> Rule("head($u, {val}) <- body($u), $u == {val}", { 'val': "abcd"})
head($u, "abcd") <- body($u), $u == "abcd"
>>> BiscuitBuilder("""
... check if right($r), {rights}.contains($r);
... """, {'rights': {'read', 'write'}})
// no root key id set
check if right($r), ["read", "write"].contains($r);
<BLANKLINE>

Rules, checks and policies can also contain parameters for public keys. Those are specified in a separate dictionnary:

>>> BlockBuilder("""
... check if admin({user}) trusting {rights_service_pubkey}
... """,
... {'user': "abcd" },
... {'rights_service_pubkey': PublicKey.from_hex("9e124fbb46ff99a87219aef4b09f4f6c3b7fd96b7bd279e38af3ef429a101c69") })
check if admin("abcd") trusting ed25519/9e124fbb46ff99a87219aef4b09f4f6c3b7fd96b7bd279e38af3ef429a101c69;
<BLANKLINE>

Whole datalog snippets
----------------------

`BiscuitBuilder()`, `BlockBuilder()` and `Authorizer()` accept whole datalog snippets, with statements separated by semicolons

>>> BiscuitBuilder("""
... user({user_id});
... check if operation("read");
... """, { 'user_id': 1234 })
// no root key id set
user(1234);
check if operation("read");
<BLANKLINE>

Individual datalog elements
---------------------------

While using `BiscuitBuilder()`, `BlockBuilder()`, `Authorizer()` works well for static datalog snippets, it is sometimes necessary to dynamically add facts, rules or policies (for instance from inside a loop or an if block).

Individual facts, rules, checks or policies can be built and added to builders like this:

>>> resources = ["file1", "file2"]
>>> builder = BiscuitBuilder("")
>>> for r in resources:
...   builder.add_fact(Fact("""right({r}, "read")""", { 'r': r}))
>>> builder
// no root key id set
right("file1", "read");
right("file2", "read");
<BLANKLINE>

In addition to `add_fact`, there are `add_rule`, `add_check`, and `add_policy`.
In addition to `Fact()`, there are `Rule()`, `Check()`, and `Policy()`.

Semicolons are not part of individual statements:

>>> Fact("user(1234)")
user(1234)
>>> Fact("user(1234);")
Traceback (most recent call last):
    ...
biscuit_auth.DataLogError: error generating Datalog: datalog parsing error: ParseErrors { errors: [ParseError { input: ";", message: Some("unexpected trailing data after fact: ';'") }] }

Supported types
---------------

Datalog supports 8 types of values (integers, strings, booleans, datetime, bytearray, set (sets cannot be nested). biscuit-python supports all of those:


.. list-table:: Types correspondence
   :header-rows: 1

   * - Python type
     - Datalog type
   * - `int`
     - `integer`
   * - `str`
     - `string`
   * - **aware** `datetime` 
     - `date`
   * - `bytes`, `list<int>`
     - `bytes`
   * - `bool`
     - `bool`
   * - `set`
     - `set`

.. warning::
   Naive dates are not supported, only aware dates: the timezone must be explictly specified (datetimes are stored as UTC timestamp with no explicit timezone information, so using UTC in python will make things simpler).

>>> from datetime import datetime, timezone
>>> now = Fact("time({now})", {'now': datetime.now(tz = timezone.utc)})
>>> Fact("time({now})", {'now': datetime(2023, 6, 9, tzinfo = timezone.utc)})
time(2023-06-09T00:00:00Z)
>>> Fact("bytes({bytes})", {'bytes': b'\xaa\xbb\xff'})
bytes(hex:aabbff)
>>> Fact("bytes({bytes})", {'bytes': [0xaa, 0xbb, 255]})
bytes(hex:aabbff)
>>> Fact("set({set})", {'set': {0, True, "ab", b'\xaa'}})
set([0, "ab", hex:aa, true])

Inspecting datalog values
-------------------------

Terms of a fact can be extracted to python values.o

>>> fact = Fact("""fact("abc", 123, hex:aa, 2023-06-09T00:00:00Z, true)""")
>>> fact.name
'fact'
>>> fact.terms
['abc', 123, [170], datetime.datetime(2023, 6, 9, 0, 0, tzinfo=datetime.timezone.utc), True]

.. warning::
   Extracting sets is not supported yet.

>>> Fact("fact([123])").terms
Traceback (most recent call last):
    ...
pyo3_runtime.PanicException: not yet implemented

