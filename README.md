# Vault Plugin: Cloudflare Access Auth Backend

## Note!  This plugin is based off a fork of the [Vault JWT Auth Plugin](https://github.com/hashicorp/vault-plugin-auth-jwt), and has just been modified to work with Cloudflare's specific implementation of OIDC, using the programmatic token verification outlined [here](https://developers.cloudflare.com/access/setting-up-access/validate-jwt-tokens/)

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin allows for Cloudflare Access specific JWTs to authenticate with Vault.

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
    - Vault Website: https://www.vaultproject.io
    - JWT Auth Docs: https://www.vaultproject.io/docs/auth/jwt.html
    - Main Project Github: https://www.github.com/hashicorp/vault

## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://www.vaultproject.io/intro/getting-started/install.html).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://www.vaultproject.io/docs/internals/plugins.html).

## Usage

Compile it using `go build` (inside the cmd/vault-plugin-auth-cloudflare-access folder, where `main.go` is)

This plugin will need to be added to Vault like so:

```sh
SHASUM=$(shasum -a 256 "<PLUGIN_BINARY_PATH>" | cut -d " " -f1) vault write sys/plugins/catalog/auth/cloudflare   sha_256="$SHASUM" \   command="vault-plugin-auth-cloudflare-access"
Success! Data written to: sys/plugins/catalog/auth/cloudflare
```

```sh
$ vault auth enable -path=cloudflare cloudflare 
Success! Enabled cloudflare method at: cloudflare/
```

## Configuration

The plugin has the following configuration options:

`default_role` The default role to be given to those logging in using this method

`auth_domain` The domain of your Cloudflare Access configuration, i.e. https://sampledomain.cloudflareaccess.com

`audience_tag` The audience tag of your Cloudflare Access application

You can set them like so:
```sh
vault write auth/cloudflare/config auth_domain=https://<AUTH_DOMAIN>.cloudflareaccess.com default_role=<my-role> audience_tag=<CF AUDIENCE TAG>
```

Create a role:

```sh
vault write auth/cloudflare/role/<my-role> policies=<my-policies> user_claim=<user_claim> groups_claim=<groups_claim>
```

where `user_claim` is probably something like `email`, and `groups_claim` is `groups`.  These are automatically pulled from Cloudflare's identity endpoint after the token is validated (see [Groups within a JWT](https://developers.cloudflare.com/access/setting-up-access/json-web-token/))

To login use your JWT you get from running 
```sh 
cloudflared access token -app=<CLOUDFLARE_APP>
```

```sh
vault write auth/cloudflare/login jwt=<JWT>
```

In order to use with the UI, you will need to use the generated token from the CLI login call.
#### Tests

## **Tests are currently broken!**

If you are developing this plugin and want to verify it is still
functioning (and you haven't broken anything else), we recommend
running the tests.

To run the tests, invoke `make test`:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='--run=TestConfig'
```
