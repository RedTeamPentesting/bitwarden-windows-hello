# Tools to Exploit Bitwarden v2023.3.0 with Windows Hello

This repository contains the tools to exploit Bitwarden v2023.3.0 when the
Windows Hello feature is enabled as described in our [blog
post](https://blog.redteam-pentesting.de/2024/bitwarden-heist/).


### Dump Keys from DPAPI

The tool `dpapidump` dumps credentials from DPAPI, including the biometric key
of Bitwarden v2023.3.0
([CVE-2023-27706](https://nvd.nist.gov/vuln/detail/CVE-2023-27706)). It can be
used as follows:

```sh
cd dpapidump
GOOS=windows go build
./dpapidump.exe
```

### Decrypt Bitwarden Vault

The Python script `hello-bitwarden.py` can be used to decrypt a Bitwarden
password vault using the biometric key obtained from DPAPI or a password. The
script can be used as follows:

```sh
./hello-bitwarden.py <path to data.json> --biometric <base64-encoded key>
./hello-bitwarden.py <path to data.json> --password <password>
```

The file `data.json` is created by Bitwarden and can usually be found at the
following path:

```
%AppData%\Bitwarden\data.json
```
