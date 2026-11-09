defmodule Samly.TestSAML do
  @moduledoc false
  # Builds SAML responses that test/data/test.pem signs as the IdP.

  import Plug.Test

  @sp %{
    id: "sp1",
    entity_id: "urn:test:sp1",
    certfile: "test/data/test.crt",
    keyfile: "test/data/test.pem"
  }

  @consume_uri "http://samly.howto:4003/sso/sp/consume/idp1"
  @audience "urn:test:sp1"
  @issuer "urn:test:idp"
  @protocol_ns "urn:oasis:names:tc:SAML:2.0:protocol"
  @assertion_ns "urn:oasis:names:tc:SAML:2.0:assertion"

  @default_session %{
    "relay_state" => "rs1",
    "idp_id" => "idp1",
    "target_url" => "/home",
    "authn_request_id" => "req-1"
  }

  def default_session, do: @default_session

  def setup_provider(idp_overrides \\ %{}) do
    idp =
      Map.merge(
        %{
          id: "idp1",
          sp_id: "sp1",
          base_url: "http://samly.howto:4003/sso",
          metadata: signing_metadata()
        },
        idp_overrides
      )

    Application.put_env(:samly, Samly.Provider,
      service_providers: [@sp],
      identity_providers: [idp]
    )

    {:ok, _} = Samly.Provider.init([])
    Samly.Helper.get_idp("idp1")
  end

  def reset_env do
    for key <- [
          Samly.Provider,
          :service_providers,
          :identity_providers,
          :idp_id_from,
          :state_store,
          :duplicate_check,
          :duplicate_release
        ] do
      Application.delete_env(:samly, key)
    end
  end

  # The IdP metadata with test/data/test.crt as the IdP signing certificate.
  def signing_metadata do
    cert_body =
      "test/data/test.crt"
      |> File.read!()
      |> String.split("\n", trim: true)
      |> Enum.reject(&String.starts_with?(&1, "-----"))
      |> Enum.join()

    "test/data/idp_metadata.xml"
    |> File.read!()
    |> String.replace(
      ~r{<ds:X509Certificate>.*?</ds:X509Certificate>}s,
      "<ds:X509Certificate>#{cert_body}</ds:X509Certificate>"
    )
  end

  def response_xml(opts \\ []) do
    in_response_to = Keyword.get(opts, :in_response_to)
    name_id = Keyword.get(opts, :name_id, "user@example.com")
    sign? = Keyword.get(opts, :sign, false)

    now = DateTime.utc_now()
    issue_instant = iso(now)
    not_before = iso(DateTime.add(now, -60, :second))
    not_on_or_after = iso(DateTime.add(now, 300, :second))

    in_response_to_attr =
      if in_response_to, do: ~s( InResponseTo="#{in_response_to}"), else: ""

    assertion =
      ~s(<saml:Assertion xmlns:saml="#{@assertion_ns}" ID="_a1" Version="2.0" ) <>
        ~s(IssueInstant="#{issue_instant}">) <>
        ~s(<saml:Issuer>#{@issuer}</saml:Issuer>) <>
        ~s(<saml:Subject><saml:NameID>#{name_id}</saml:NameID>) <>
        ~s(<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">) <>
        ~s(<saml:SubjectConfirmationData Recipient="#{@consume_uri}" ) <>
        ~s(NotOnOrAfter="#{not_on_or_after}"#{in_response_to_attr}/>) <>
        ~s(</saml:SubjectConfirmation></saml:Subject>) <>
        ~s(<saml:Conditions NotBefore="#{not_before}" NotOnOrAfter="#{not_on_or_after}">) <>
        ~s(<saml:AudienceRestriction><saml:Audience>#{@audience}</saml:Audience>) <>
        ~s(</saml:AudienceRestriction></saml:Conditions>) <>
        ~s(<saml:AuthnStatement AuthnInstant="#{issue_instant}" SessionIndex="_s1">) <>
        ~s(<saml:AuthnContext><saml:AuthnContextClassRef>) <>
        ~s(urn:oasis:names:tc:SAML:2.0:ac:classes:Password) <>
        ~s(</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>) <>
        ~s(</saml:Assertion>)

    assertion = if sign?, do: sign(assertion), else: assertion

    ~s(<samlp:Response xmlns:samlp="#{@protocol_ns}" xmlns:saml="#{@assertion_ns}" ) <>
      ~s(ID="_r1" Version="2.0" IssueInstant="#{issue_instant}">) <>
      ~s(<saml:Issuer>#{@issuer}</saml:Issuer>) <>
      ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>) <>
      ~s(</samlp:Status>) <>
      assertion <>
      ~s(</samlp:Response>)
  end

  def post_consume(xml, session \\ @default_session, relay_state \\ "rs1") do
    conn(:post, "/sp/consume/idp1", %{
      "SAMLResponse" => Base.encode64(xml),
      "RelayState" => relay_state
    })
    |> init_test_session(session)
    |> Samly.Router.call(Samly.Router.init([]))
  end

  # The esaml fork refuses this payload with {error, doctype_not_allowed}.
  def doctype_xml do
    ~s(<!DOCTYPE samlp:Response [<!ENTITY x "y">]>) <>
      ~s(<samlp:Response xmlns:samlp="#{@protocol_ns}">&x;</samlp:Response>)
  end

  @slo_uri "http://samly.howto:4003/sso/sp/logout/idp1"

  # A LogoutResponse from the IdP. With doctype: true, it has a DOCTYPE.
  def logout_response_xml(opts \\ []) do
    doctype(:LogoutResponse, opts) <>
      ~s(<samlp:LogoutResponse xmlns:samlp="#{@protocol_ns}" xmlns:saml="#{@assertion_ns}" ) <>
      ~s(ID="_lr1" Version="2.0" IssueInstant="#{iso(DateTime.utc_now())}" ) <>
      ~s(Destination="#{@slo_uri}" InResponseTo="_lq0">) <>
      ~s(<saml:Issuer>#{@issuer}</saml:Issuer>) <>
      ~s(<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>) <>
      ~s(</samlp:Status></samlp:LogoutResponse>)
  end

  # A LogoutRequest that test/data/test.pem signs as the IdP.
  # With doctype: true, it has a DOCTYPE.
  def logout_request_xml(opts \\ []) do
    request =
      ~s(<samlp:LogoutRequest xmlns:samlp="#{@protocol_ns}" xmlns:saml="#{@assertion_ns}" ) <>
        ~s(ID="_lq1" Version="2.0" IssueInstant="#{iso(DateTime.utc_now())}" ) <>
        ~s(Destination="#{@slo_uri}">) <>
        ~s(<saml:Issuer>#{@issuer}</saml:Issuer>) <>
        ~s(<saml:NameID>user@example.com</saml:NameID>) <>
        ~s(<samlp:SessionIndex>_s1</samlp:SessionIndex>) <>
        ~s(</samlp:LogoutRequest>)

    doctype(:LogoutRequest, opts) <> sign(request)
  end

  defp doctype(root, opts) do
    if Keyword.get(opts, :doctype, false),
      do: ~s(<!DOCTYPE samlp:#{root} [<!ENTITY x "y">]>),
      else: ""
  end

  # Posts a SAMLResponse or a SAMLRequest to the sign-out route.
  def post_logout(param, xml) do
    conn(:post, "/sp/logout/idp1", %{param => Base.encode64(xml), "RelayState" => "rs1"})
    |> init_test_session(%{"relay_state" => "rs1", "idp_id" => "idp1", "target_url" => "/"})
    |> Samly.Router.call(Samly.Router.init([]))
  end

  # Calls Samly.AuthHandler.send_signin_req/1 directly. This skips the CSRF check.
  def send_signin(idp) do
    conn(:post, "/auth/signin/idp1")
    |> init_test_session(%{})
    |> Plug.Conn.put_private(:samly_idp, idp)
    |> Plug.Conn.put_private(:samly_nonce, "n")
    |> Plug.Conn.put_private(:samly_target_url, "/home")
    |> Samly.AuthHandler.send_signin_req()
  end

  # Returns the value of a hidden form field in an esaml HTTP-POST page.
  def form_value(body, name) do
    [_, value] = Regex.run(~r/name="#{name}" value="([^"]*)"/, body)
    value
  end

  defp sign(assertion) do
    key = :esaml_util.load_private_key(~c"test/data/test.pem")
    cert = :esaml_util.load_certificate(~c"test/data/test.crt")
    {el, _} = :xmerl_scan.string(String.to_charlist(assertion), namespace_conformant: true)
    signed = :xmerl_dsig.sign(el, key, cert)
    :xmerl.export_simple([signed], :xmerl_xml, prolog: []) |> IO.chardata_to_string()
  end

  defp iso(dt), do: dt |> DateTime.truncate(:second) |> DateTime.to_iso8601()
end
