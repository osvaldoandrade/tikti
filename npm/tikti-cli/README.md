# @osvaldoandrade/tikti-cli

Tikti admin CLI distributed as a prebuilt Go binary downloaded from GitHub Releases during `npm install`.

## Install (GitHub Packages)

1) Authenticate to GitHub Packages (requires a token with `read:packages`):

```sh
npm config set @osvaldoandrade:registry https://npm.pkg.github.com
npm config set //npm.pkg.github.com/:_authToken YOUR_GITHUB_TOKEN
```

2) Install:

```sh
npm install -g @osvaldoandrade/tikti-cli
```

## Upgrade

```sh
npm install -g @osvaldoandrade/tikti-cli@latest
```

## Notes

- If the repository is private, you may need `GITHUB_TOKEN`/`GH_TOKEN` set so the postinstall binary download can authenticate.

