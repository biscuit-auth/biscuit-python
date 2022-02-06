# Overview

This is a _very_ experimental take on Python bindings for the [biscuit_auth](https://docs.rs/biscuit-auth/latest/biscuit_auth/) Rust library. It is very much a work in progress (limited testing, most errors are dropped on the floor, etc). Please don't use this for anything in its current state.

Hopefully someday this leads to a production-ready Biscuit library for Python, but this is (currently) not that, and there will definitely be significant API changes before that happens.

This project borrows quite heavily from the approach (and in many cases the actual code) of the [biscuit-wasm](https://github.com/biscuit-auth/biscuit-wasm) project.

# Building/Testing

Set up a virtualenv and install the dev dependencies. Plenty of ways to do that... Here's one of them:

```
$ python -m venv .env
$ source .env/bin/activate
$ pip install -r requirements-dev.txt
```

With that, you should be able to run `maturin develop` to build and install the extension. You can then `import biscuit_auth` in a Python shell to play around, or run `pytest` to run the Python tests.