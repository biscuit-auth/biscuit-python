# Python bindings for biscuit

This library provides python bindings to the [biscuit_auth](https://docs.rs/biscuit-auth/latest/biscuit_auth/) rust library.

As it is a pre-1.0 version, you can expect some API changes. However, most of the use cases are covered:

- building a token
- appending a (first-party) block to a token
- parsing a token
- authorizing a token
- querying an authorizer

Notable missing features are:

- sealing tokens
- third-party blocks
- snapshots

There are no blockers for these features, they just have not been properly exposed yet.

## Documentation

Documentation is available at <https://python.biscuitsec.org>.

## Installation

`biscuit-python` is published on PyPI: [biscuit-python](https://pypi.org/project/biscuit-python/):

```
pip install biscuit-python
```

## Building/Testing

Set up a virtualenv and install the dev dependencies. Plenty of ways to do that... Here's one of them:

```
$ python -m venv .env
$ source .env/bin/activate
$ pip install -r requirements-dev.txt
```

With that, you should be able to run `maturin develop` to build and install the extension. You can then `import biscuit_auth` in a Python shell to play around, or run `pytest` to run the Python tests.