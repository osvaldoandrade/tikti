# @osvaldoandrade/tikti-cli

tikti-cli is the admin CLI for Tikti. It ships as a prebuilt Go binary that the npm postinstall hook downloads from GitHub Releases, so no Go toolchain is required on the target machine. The binary supports tenant management, authentication, and SAML 2.0 federation commands.

## Install

```sh
npm install -g @osvaldoandrade/tikti-cli
```

## Upgrade

```sh
npm install -g @osvaldoandrade/tikti-cli@latest
```

## Usage

```sh
tikti-cli init --base-url http://localhost:8080 --api-key <key> --tenant <tid>
tikti-cli auth login --email admin@example.com
tikti-cli saml metadata
tikti-cli saml idp register --tenant <tenantId> --metadata-url <url>
tikti-cli saml idp show --tenant <tenantId>
tikti-cli saml keys rotate
```

`init` persists connection details for subsequent commands. `auth login` authenticates against the Tikti API. The `saml` subcommands manage SAML 2.0 federation: `metadata` prints the SP metadata document, `idp register` adds an identity provider to a tenant, `idp show` displays the registered identity provider, and `keys rotate` replaces the SP signing keypair.

## Notes

- If the repository is private, set `GITHUB_TOKEN` or `GH_TOKEN` so the postinstall binary download can authenticate with GitHub.
