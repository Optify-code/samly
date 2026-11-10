# Samly

A SAML 2.0 Service Provider Single-Sign-On Authentication library. This Plug library can be used to SAML enable a Plug/Phoenix application.

This has been used in the wild with the following Identity Providers:

+ Okta
+ Ping Identity
+ OneLogin
+ ADFS
+ Nexus GO
+ Shibboleth
+ SimpleSAMLphp
+ Google

This library uses Erlang [`esaml`](https://github.com/dropbox/esaml) to provide plug enabled routes.

## Setup

```elixir
# mix.exs

# v1.0.0 uses esaml v4.2 which in turn relies on cowboy 2.x
# If you need to work with cowboy 1.x, you need the following override:
# {:esaml, "~> 3.7", override: true}

defp deps() do
  [
    # ...
    {:samly, "~> 1.0"},
  ]
end
```

## Supervision Tree

Add `Samly.Provider` to your application supervision tree.

```elixir
# application.ex

children = [
  # ...
  {Samly.Provider, []}
]
```

## Router Change

Make the following change in your application router.

```elixir
# router.ex

# Add the following scope ahead of other routes
# Keep this as a top-level scope and **do not** add
# any plugs or pipelines explicitly to this scope.
scope "/sso" do
  forward "/", Samly.Router
end
```

## Certificate and Key for Samly

`Samly` needs a private key and a corresponding certificate. These are used to
sign the SAML requests when communicating with the Identity Provider. This certificate
should be made available to `Samly` via config settings. It should also be made
available to the Identity Provider so it can verify the SAML signed requests.

You can create a self-signed certificate for this purpose. You can use `phx.gen.cert`
mix task that is available as part of Phoenix 1.4 or use `openssl` directly to generate
the key and corresponding certificate.
(Check out [`samly_howto`](https://github.com/dropbox/samly_howto) `README.md` for this.)

## Identity Provider Metadata

`Samly` expects information about the Identity Provider including information about
its SAML endpoints in an XML file. Most Identity Providers have some way of
exporting the IdP metadata in XML form. Some may provide a web UI to export/save
the XML locally. Others may provide a URL that can be used to fetch the metadata.

For example, `SimpleSAMLPhp` IdP provides a URL for the metadata. You can fetch
it using `wget`.

```
wget --no-check-certificate -O idp1_metadata.xml https://idp1.samly:9091/simplesaml/saml2/idp/metadata.php
```

If you are using the `SimpleSAMLPhp` administrative Web UI, login with you
admin credentials (`https://idp1.samly:9091/simplesaml`). Go to the `Federation`
tab. At the top there will be a section titled "SAML 2.0 IdP Metadata". Click
on the `Show metadata` link. Copy the metadata XML from this page and save it
in a local file (`idp1_metadata.xml` for example).

Make sure to save this XML file and provide the path to the saved file in
`Samly` configuration.

## Identity Provider ID in Samly

`Samly` has the ability to support multiple Identity Providers. All IdPs that
`Samly` needs to talk to must have an identifier (idp_id). This IdP id will be
used in the service provider URLs. This is how `Samly` figures out which SAML
request corresponds to what IdP so that it can perform relevant validation checks
and process the requests/responses.

There are two options when it comes to how the idp_id is represented in the
Service Provider SAML URLs.

#### URL Path Segment

In this model, the idp_id is present as a URL path segment. Here is an
example URL: `https://do-good.org/sso/auth/signin/affiliates`. The idp_id
in this URL is "affiliates". If you have more than one IdP, only this last
part changes. The URLs for this model are:

| Description | URL |
|:----|:----|
| Sign-in button/link in Web UI | `/sso/auth/signin/affiliates` |
| Sign-out button/link in Web UI | `/sso/auth/signout/affiliates` |
| SP Metadata URL | `https://do-good.org/sso/sp/metadata/affiliates` |
| SAML Assertion Consumer Service | `https://do-good.org/sso/sp/consume/affiliates` |
| SAML SingleLogout Service | `https://do-good.org/sso/sp/logout/affiliates` |

The path segment model is the default one in `Samly`. If there is only one Identity Provider, use this mode.

> These URL routes are automatically created based on the configuration information and
> the above mentioned router scope definition.
>
> Use the Sign-in and Sign-out URLs shown above in your application's Web UI buttons/links.
> When the end-user clicks on these buttons/links, the HTTP `GET` request is handled by `Samly`
> which internally does a `POST` that in turn sends the appropriate SAML request to the IdP.

#### Subdomain in Host Name

In this model, the subdomain name is used as the idp_id. Here is an example URL: `https://ngo.do-good.org/sso/auth/signin`. Here `ngo` is the idp_id. The URLs supported by `Samly`
in this model look different.

| Description | URL |
|:----|:----|
| Sign-in button/link in Web UI | `/sso/auth/signin` |
| Sign-out button/link in Web UI | `/sso/auth/signout` |
| SP Metadata URL | `https://ngo.do-good.org/sso/sp/metadata` |
| SAML Assertion Consumer Service | `https://ngo.do-good.org/sso/sp/consume` |
| SAML SingleLogout Service | `https://ngo.do-good.org/sso/sp/logout` |

> Take a look at [`samly_howto`](https://github.com/dropbox/samly_howto) - a reference/demo
> application on how to use this library.
>
> Make sure to use HTTPS URLs in production deployments.

#### Target URL for Sign-In and Sign-Out Actions

The sign-in and sign-out URLs (HTTP GET) mentioned above optionally take a `target_url`
query parameter. `Samly` will redirect the browser to these URLs upon successfully
completing the sign-in/sign-out operations initiated from your application.

> This `target_url` query parameter value must be `x-www-form-urlencoded`.

## Samly Configuration

```elixir
# config/dev.exs

config :samly, Samly.Provider,
  idp_id_from: :path_segment,
  service_providers: [
    %{
      id: "do-good-affiliates-sp",
      entity_id: "urn:do-good.org:affiliates-app",
      certfile: "path/to/samly/certfile.pem",
      keyfile: "path/to/samly/keyfile.pem",
      #contact_name: "Affiliates Admin",
      #contact_email: "affiliates-admin@do-good.org",
      #org_name: "Do Good",
      #org_displayname: "Goodly, No evil!",
      #org_url: "https://do-good.org"
    }
  ],
  identity_providers: [
    %{
      id: "affiliates",
      sp_id: "do-good-affiliates-sp",
      base_url: "https://do-good.org/sso",
      metadata_file: "idp1_metadata.xml",
      #pre_session_create_pipeline: MySamlyPipeline,
      #use_redirect_for_req: false,
      #sign_requests: true,
      #sign_metadata: true,
      #signed_assertion_in_resp: true,
      #signed_envelopes_in_resp: true,
      #allow_idp_initiated_flow: false,
      #allowed_target_urls: ["https://do-good.org"],
      #nameid_format: :transient
    }
  ]
```

| Parameters | Description |
|:------------|:-----------|
| `idp_id_from` | _(optional)_`:path_segment` or `:subdomain`. Default is `:path_segment`. |
| **Service Provider Parameters** | |
| `id` | _(mandatory)_ |
| `identity_id` | _(optional)_ If omitted, the metadata URL will be used |
| `certfile` | _(optional)_ This is needed when SAML requests/responses from `Samly` need to be signed. Make sure to **set this in a production deployment**. Could be omitted during development if your IDP is setup to not require signing. If that is the case, the following **Identity Provider Parameters** must be explicitly set to false: `sign_requests`, `sign_metadata`|
| `keyfile` | _(optional)_ Similar to `certfile` |
| `contact_name` | _(optional)_ Technical contact name for the Service Provider |
| `contact_email` | _(optional)_ Technical contact email address |
| `org_name` | _(optional)_ SAML Service Provider (your app) Organization name |
| `org_displayname` | _(optional)_ SAML SP Organization displayname |
| `org_url` | _(optional)_ Service Provider Organization web site URL |
| **Identity Provider Parameters** | |
| `id` | _(mandatory)_ This will be the idp_id in the URLs |
| `sp_id` | _(mandatory)_ The service provider definition to be used with this Identity Provider definition |
| `base_url` | _(optional)_ If missing `Samly` will use the current URL to derive this. It is better to define this in production deployment. |
| `metadata_file` | _(mandatory if `metadata` is not set)_ Path to the IdP metadata XML file obtained from the Identity Provider. This will be ignored if `metadata` is non-nil. |
| `metadata` | _(mandatory if `metadata_file` is not set))_ String containing IdP metadata XML obtained from the Identity Provider. |
| `pre_session_create_pipeline` | _(optional)_ Check the customization section. |
| `use_redirect_for_req` | _(optional)_ Default is `false`. When this is `false`, `Samly` will POST to the IdP SAML endpoints. |
| `sign_requests`, `sign_metadata` | _(optional)_ Default is `true`. |
| `signed_assertion_in_resp`, `signed_envelopes_in_resp` | _(optional)_ Default is `true`. When `true`, `Samly` expects the requests and responses from IdP to be signed. |
| `allow_idp_initiated_flow` | _(optional)_ Default is `false`. When this is `false`, `Samly` refuses an unsolicited response (one without `InResponseTo`). When this is `true`, `Samly` does not sign in from an unsolicited response. It sends the browser through an SP-initiated sign-in at the same IdP instead, so a user who starts at the IdP portal signs in after one more redirect. A second unsolicited response in a row is refused. |
| `allowed_target_urls` | _(optional)_ Default is `[]`. `Samly` uses this **only** when `allow_idp_initiated_flow` parameter is set to `true`. Make sure to set this to one or more exact URLs you want to allow (whitelist). The URL to redirect the user after completing the SSO flow is sent from IDP in auth response as `relay_state`. This `relay_state` target URL is matched against this URL list, and becomes the target of the SP-initiated sign-in. Set the value to `nil` if you do not want this whitelist capability. With `nil`, only a path on this site is kept, and any other `relay_state` goes to `/`. |
| `nameid_format` | _(optional)_ When specified, `Samly` includes the value as the `NameIDPolicy` element's `Format` attribute in the login request. Value must either be a string or one of the following atoms: `:email`, `:x509`, `:windows`, `:krb`, `:persistent`, `:transient`. Use the string value when you need to specify a non-standard/custom nameid format supported by your IdP. |

#### Authenticated SAML Assertion State Store

`Samly` internally maintains the authenticated SAML assertions (from `LoginResponse` SAML requests).
There are two built-in state store options available - one based on ETS and the other on Plug Sessions.
The ETS store can be setup using the following configuration:

```elixir
config :samly, Samly.State,
  store: Samly.State.ETS,
  opts: [table: :my_ets_table]
```

This state configuration is optional. If omitted, `Samly` uses `Samly.State.ETS` provider by default.

| Options | Description |
|:------------|:-----------|
| `opts` | _(optional)_ The `:table` option is the ETS table name for storing the assertions. This ETS table is created during the store provider initialization if it is not already present. Default is `samly_assertions_table`. |

> Use `Samly.State.Session` provider in a clustered deployment. This provider uses
> the Plug Sessions to keep the authenticated SAML assertions.

This session based provider can be enabled using the following:

```elixir
config :samly, Samly.State,
  store: Samly.State.Session,
  opts: [key: :my_assertion_key]
```

| Options | Description |
|:------------|:-----------|
| `opts` | _(optional)_ The `:key` is the name of the session key where assertion is stored. Default is `:samly_assertion`. |

## SAML Assertion

Once authentication is completed successfully, IdP sends a "consume" SAML
request to `Samly`. `Samly` in-turn performs its own checks (including checking
the integrity of the "consume" request). At this point, the SAML assertion
with the authenticated user subject and attributes is available.

The subject in the SAML assertion is tracked by `Samly` so that subsequent
logout/signout request, either service provider initiated or IdP initiated
would result in proper removal of the corresponding SAML assertion.

Use the `Samly.get_active_assertion` function to get the SAML assertion
for the currently authenticated user. This function will return `nil` if
the user is not authenticated.

> Avoid using the subject in the SAML assertion in UI. Depending on how the
> IdP is setup, this might be a randomly generated id.
>
> You should only rely on the user attributes in the assertion.
> As an application working with an IdP, you should know which attributes
> will be made available to your application and out of
> those attributes which one should be treated as the logged in userid/name.
> For example it could be "uid" or "email" depending on how the authentication
> source is setup in the IdP.

## Customization

#### Pipeline

`Samly` allows you to specify a Plug Pipeline if you need more control over
the authenticated user's attributes and/or do a Just-in-time user creation.
The Plug Pipeline is invoked after the user has successfully authenticated
with the IdP but before a session is created.

This is just a vanilla Plug Pipeline. The SAML assertion from
the IdP is made available in the Plug connection as a "private".
(The pipeline plugs have access to the `idp_id` in this assertion.)
If you want to derive new attributes, create an Elixir map data (`%{}`)
and update the `computed` field of the SAML assertion and put it back
in the Plug connection private with `Conn.put_private` call.

Here is a sample pipeline that shows this:

```elixir
defmodule MySamlyPipeline do
  use Plug.Builder
  alias Samly.{Assertion}

  plug :compute_attributes
  plug :jit_provision_user

  def compute_attributes(conn, _opts) do
    assertion = conn.private[:samly_assertion]

    # This assertion has the idp_id
    # %Assertion{idp_id: idp_id} = assertion

    first_name = Map.get(assertion.attributes, "first_name")
    last_name  = Map.get(assertion.attributes, "last_name")

    computed = %{"full_name" => "#{first_name} #{last_name}"}

    assertion = %Assertion{assertion | computed: computed}

    conn
    |>  put_private(:samly_assertion, assertion)

    # If you have an error condition:
    # conn
    # |>  send_resp(404, "attribute mapping failed")
    # |>  halt()
    #
    # Halt only before you create a session. See the duplicate check under
    # "Security Related".
  end

  def jit_provision_user(conn, _opts) do
    # your user creation here ...
    conn
  end
end
```

Make this pipeline available in your config:

```elixir
config :samly, Samly.Provider,
  identity_providers: [
    %{
      # ...
      pre_session_create_pipeline: MySamlyPipeline,
      # ...    
    }
  ]
```

#### State Store

Take a look at the implementation of `Samly.State.ETS` or `Samly.State.Session` and use those as examples showing how to create your own state store (based on redis, memcached, database etc.).

## Security Related

+   `Samly` initiated sign-in/sign-out requests send `RelayState` to IdP and expect to get that back. Mismatched or missing `RelayState` in IdP responses to SP initiated requests will fail (with HTTP `403 access_denied`).
+   Besides the `RelayState`, the request and response `idp_id`s must match. Response is rejected if they don't.
+   `Samly` can check each assertion for **replay attacks**. Set a duplicate check in the application config:

    ```elixir
    config :samly, :duplicate_check, {MyApp.SAML, :check_assertion, []}
    ```

    `Samly` calls `MyApp.SAML.check_assertion(assertion, digest, ...extra args)` for each valid assertion.
    `assertion` is a `Samly.Assertion` with `idp_id` set.
    `digest` is a SHA-256 digest of the assertion fields that `esaml` decodes.
    These fields come only from the signed assertion.
    Thus, a change to an unsigned Response attribute or to the encryption does not change the digest.
    Return `:ok` to accept the assertion.
    Any other value refuses the response with HTTP `403 access_denied :duplicate`.
    > The check runs after the `esaml` signature and validity checks and after the `Samly` `RelayState`, `idp_id` and `InResponseTo` checks.
    > It runs before the `pre_session_create_pipeline`. Thus, a pipeline does not run for a refused replay.
    > A response that one of these earlier checks refuses does not reach the check, so a later retry is not refused as a duplicate.
    > In a cluster, use a shared store with an atomic claim, for example a unique index in a database.
    > An exception in the function propagates to the caller, and the request fails with HTTP 500.
    > With no setting, `Samly` does not check for replayed assertions. The single-use request ID below still applies.

    Set a release function to remove a claim when `Samly` does not accept the assertion:

    ```elixir
    config :samly, :duplicate_release, {MyApp.SAML, :release_assertion, []}
    ```

    `Samly` calls `MyApp.SAML.release_assertion(assertion, digest, ...extra args)` only when the `pre_session_create_pipeline` halts.
    Then no session exists, and a retry of the same response can sign in.
    `Samly` ignores the return value.
    > Without a release function, the claim stays. A retry of the same response is then refused as a duplicate.

    The `pre_session_create_pipeline` must follow this contract:
    +   Halt only before you create a session. A halt tells `Samly` that the pipeline refused the sign-in, so `Samly` releases the claim.
    +   After a session exists, do not halt.
    +   A raise from the pipeline or from the state store always keeps the claim. `Samly` cannot know whether the pipeline already signed the user in, so it fails closed. The same response then cannot be posted again, and the user starts a new sign-in.
+   SP-initiated sign-in stores the AuthnRequest ID in the session.
    `Samly` reads `InResponseTo` from the signed `SubjectConfirmationData` of the assertion.
    When `InResponseTo` differs from the stored ID, `Samly` refuses the response with HTTP `403 access_denied :invalid_in_response_to`.
    Each request ID signs in one time only:
    +   An accepted SP-initiated response claims its request ID in an ETS table on the node. The claim is atomic.
    +   A second response to the same request ID gets HTTP `403 access_denied :invalid_in_response_to`. This applies to two requests at the same time and to an old session cookie.
    +   An accepted SP-initiated response also deletes the stored ID from the session. An IdP-initiated response does not delete it.
    +   When the `pre_session_create_pipeline` halts, `Samly` releases the claim. A raise from the pipeline or the state store keeps it.
    > The ETS table is local to each node. In a cluster, a response can go to a different node.
    > To make each response single use across the cluster, set the duplicate check above. Claim the digest or `subject.in_response_to` in a shared store.
    > A sign-in that started before the upgrade has no stored ID.
    > `Samly` refuses its response one time, and the user must sign in again.
+   OOTB SAML requests and responses are signed.
+   Signature digest method supported: `SHA256`.
    > Some Identity Providers may be using `SHA1` by default.
    > Make sure to configure the IdP to use `SHA256`. `Samly`
    > will reject (`access_denied`) IdP responses using `SHA1`.
+   `esaml` provides additional checks such as trusted certificate verification, recipient verification among others.
+   By default, `Samly` signs the SAML requests it sends to the Identity Provider. It also
    expects the SAML reqsponses to be signed (both assertion and envelopes). If your IdP is
    not configured to sign, you will have to explicitly turn them off in the configuration.
    It is highly recommended to turn signing on in production deployments.
+   Encrypted Assertions are supported in `Samly`. There are no explicit config settings for this. Decryption happens automatically when encrypted assertions are detected in the SAML response.
    > [Supported Encryption algorithms](https://github.com/dropbox/esaml#assertion-encryption)
+   Make sure to use HTTPS URLs in production deployments.

## FAQ

#### How to setup a SAML 2.0 IdP for development purposes?

Docker based setup of [`SimpleSAMLPhp`](https://simplesamlphp.org) is made available
at [`samly_simplesaml`](https://github.com/dropbox/samly_simplesaml) Git Repo.
Check out the `README.md` file of this repo.

There is also a Docker based setup of [`Shibboleth`](https://www.shibboleth.net/).
Checkout the corresponding `README.md` file in [`samly_shibboleth`](https://github.com/dropbox/samly_shibboleth) Git Repo.

#### Any sample Phoenix application that shows how to use Samly?

Clone the [`samly_howto`](https://github.com/dropbox/samly_howto) Git Repo.
Detailed instructions on how to setup and run this application are available
in the `README.md` file in this repo.

> It is recommended that you use the `SamlyHowto` application to
> sort out any configuration issues by making that demo application work
> successfully with your Identity Provider (IdP) before attempting your
> application.
>
> This demo application supports experimentation with multiple IdPs.

#### How to register the service provider with IdP

If you are using `samly_simplesaml` or `samly_shibboleth`, the instructions
you followed there would take care of registering your Phoenix SAML Service provider
appliccation. For any other IdP, follow the instructions from the respective
IdP vendor.

#### Common Errors

`access_denied {:error, :bad_recipient}` - Check the `base_url` in your `Samly`
config setting under `indentity_providers`.

`access_denied {:error, :bad_audience}` - Make sure that the `entity_id` in
the `Samly` config setting is correct.

`access_denied {:envelope, {:error, :cert_no_accepted}}` - Make sure the
Identity Provider metadata XML file you are using in the `Samly` config setting
is correct and corresponds to the IdP you are attempting to talk to. You get
this error if the certificate used by the IdP to sign the SAML responses
has changed and you don't have the updated IdP metadata XML file on the `Samly` end.
