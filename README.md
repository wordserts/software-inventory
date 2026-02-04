# installed extension

## Building and signing

* `dt-sdk build .`

## Running

* `dt-sdk run`

## Developing

1. Clone this repository
2. Install dependencies with `pip install .`
3. Increase the version under `extension/extension.yaml` after modifications
4. Run `dt-sdk build`

## Structure

### installed folder

Contains the python code for the extension

### extension folder

Contains the yaml and activation definitions for the framework v2 extension

### setup.py

Contains dependency and other python metadata

### activation.json

Used during simulation only, contains the activation definition for the extension


### Signing
```
dt-sdk build -e manylinux2014_x86_64 -e win_amd64
```

https://docs.dynatrace.com/docs/ingest-from/extensions/develop-your-extensions/sign-extensions/manually-openssl
```

```