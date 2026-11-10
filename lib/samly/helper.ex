defmodule Samly.Helper do
  @moduledoc false

  require Samly.Esaml
  import SweetXml, only: [sigil_x: 2, xpath: 2]
  alias Samly.{Assertion, Esaml, IdpData, UsedRequestIds}

  @spec get_idp(binary) :: nil | IdpData.t()
  def get_idp(idp_id) do
    idps = Application.get_env(:samly, :identity_providers, %{})
    Map.get(idps, idp_id)
  end

  @spec get_metadata_uri(nil | binary, binary) :: nil | charlist
  def get_metadata_uri(nil, _idp_id), do: nil

  def get_metadata_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/metadata" |> String.to_charlist()
  end

  def get_metadata_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/metadata/#{idp_id}" |> String.to_charlist()
  end

  @spec get_consume_uri(nil | binary, binary) :: nil | charlist
  def get_consume_uri(nil, _idp_id), do: nil

  def get_consume_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/consume" |> String.to_charlist()
  end

  def get_consume_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/consume/#{idp_id}" |> String.to_charlist()
  end

  @spec get_logout_uri(nil | binary, binary) :: nil | charlist
  def get_logout_uri(nil, _idp_id), do: nil

  def get_logout_uri(sp_base_url, nil) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/logout" |> String.to_charlist()
  end

  def get_logout_uri(sp_base_url, idp_id) when is_binary(sp_base_url) do
    "#{sp_base_url}/sp/logout/#{idp_id}" |> String.to_charlist()
  end

  def sp_metadata(sp) do
    :xmerl.export([:esaml_sp.generate_metadata(sp)], :xmerl_xml)
  end

  def gen_idp_signin_req(sp, idp_metadata, nameid_format) do
    idp_signin_url = Esaml.esaml_idp_metadata(idp_metadata, :login_location)

    xml_frag = :esaml_sp.generate_authn_request(idp_signin_url, sp, nameid_format)

    {idp_signin_url, xml_frag}
  end

  # Returns the ID attribute of the root element of an AuthnRequest.
  @spec authn_request_id(tuple) :: String.t()
  def authn_request_id(xml_frag) do
    xpath(xml_frag, ~x"./@ID"s)
  end

  def gen_idp_signout_req(sp, idp_metadata, subject_rec, session_index) do
    idp_signout_url = Esaml.esaml_idp_metadata(idp_metadata, :logout_location)
    xml_frag = :esaml_sp.generate_logout_request(idp_signout_url, session_index, subject_rec, sp)
    {idp_signout_url, xml_frag}
  end

  def gen_idp_signout_resp(sp, idp_metadata, signout_status) do
    idp_signout_url = Esaml.esaml_idp_metadata(idp_metadata, :logout_location)
    xml_frag = :esaml_sp.generate_logout_response(idp_signout_url, signout_status, sp)
    {idp_signout_url, xml_frag}
  end

  def decode_idp_auth_resp(sp, saml_encoding, saml_response) do
    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
         {:ok, assertion_rec} <- :esaml_sp.validate_assertion(xml_frag, sp) do
      assertion = Assertion.from_rec(assertion_rec)
      {:ok, assertion, assertion_digest(assertion)}
    else
      {:error, reason} -> {:error, reason}
      error -> {:error, {:invalid_request, "#{inspect(error)}"}}
    end
  end

  # SHA-256 over the assertion fields that esaml decoded.
  # These fields come only from the assertion, which the IdP signs.
  # Thus, a change to an unsigned Response attribute or to the encryption
  # does not change the digest.
  @spec assertion_digest(Assertion.t()) :: binary
  def assertion_digest(%Assertion{} = assertion) do
    fields = %Assertion{assertion | computed: %{}, idp_id: ""}
    :crypto.hash(:sha256, canonical(fields))
  end

  defp canonical(value) when is_binary(value),
    do: ["s", Integer.to_string(byte_size(value)), ":", value]

  defp canonical(value) when is_atom(value), do: ["a", canonical(Atom.to_string(value))]

  defp canonical(value) when is_list(value),
    do: ["l", Integer.to_string(length(value)), ":", Enum.map(value, &canonical/1)]

  defp canonical(%_{} = value), do: value |> Map.from_struct() |> canonical()

  defp canonical(%{} = value) do
    pairs =
      value
      |> Enum.map(fn {k, v} -> {to_string(k), v} end)
      |> Enum.sort()
      |> Enum.map(fn {k, v} -> [canonical(k), canonical(v)] end)

    ["m", Integer.to_string(map_size(value)), ":", pairs]
  end

  @doc false
  # Claims the assertion before samly runs the pre-session pipeline:
  #   1. An SP-initiated response claims its InResponseTo on this node.
  #   2. The function in `config :samly, :duplicate_check` claims the assertion.
  # A refused or failed claim releases the claims that it made before.
  # release_assertion/2 releases both claims when the pre-session pipeline halts.
  @spec claim_assertion(Assertion.t(), binary) ::
          :ok | {:error, :invalid_in_response_to | :duplicate}
  def claim_assertion(%Assertion{} = assertion, digest) do
    with :ok <- claim_request_id(assertion) do
      try do
        check_duplicate(assertion, digest)
      catch
        kind, reason ->
          release_request_id(assertion)
          :erlang.raise(kind, reason, __STACKTRACE__)
      else
        :ok ->
          :ok

        error ->
          release_request_id(assertion)
          error
      end
    end
  end

  @doc false
  # Releases the claims of claim_assertion/2. samly calls it only when the
  # pre-session pipeline halts. Then the same response can sign in on a retry.
  # A raise keeps the claims, because the pipeline may have signed the user in.
  @spec release_assertion(Assertion.t(), binary) :: :ok
  def release_assertion(%Assertion{} = assertion, digest) do
    release_request_id(assertion)

    if Application.get_env(:samly, :duplicate_check) != nil do
      case callback(:duplicate_release) do
        nil -> :ok
        {mod, fun, args} -> apply(mod, fun, [assertion, digest | args])
      end
    end

    :ok
  end

  defp claim_request_id(%Assertion{subject: %{in_response_to: ""}}), do: :ok

  defp claim_request_id(%Assertion{idp_id: idp_id, subject: subject} = assertion) do
    UsedRequestIds.claim(idp_id, subject.in_response_to, stale_time(assertion))
  end

  defp release_request_id(%Assertion{subject: %{in_response_to: ""}}), do: :ok

  defp release_request_id(%Assertion{idp_id: idp_id, subject: subject}) do
    UsedRequestIds.release(idp_id, subject.in_response_to)
  end

  # The Unix time after which esaml refuses the assertion as stale.
  # It uses the same rule as esaml:stale_time/1.
  defp stale_time(%Assertion{} = assertion) do
    limits =
      [assertion.subject.notonorafter, assertion.conditions["not_on_or_after"]]
      |> Enum.map(&unix_time/1)
      |> Enum.reject(&is_nil/1)

    case limits do
      [] -> (unix_time(assertion.issue_instant) || System.os_time(:second)) + 5 * 60
      _ -> Enum.min(limits)
    end
  end

  defp unix_time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> DateTime.to_unix(datetime)
      _ -> nil
    end
  end

  defp unix_time(_), do: nil

  # Calls the function in `config :samly, :duplicate_check`.
  # A return value other than :ok refuses the assertion.
  @spec check_duplicate(Assertion.t(), binary) :: :ok | {:error, :duplicate}
  def check_duplicate(%Assertion{} = assertion, digest) do
    case callback(:duplicate_check) do
      nil ->
        :ok

      {mod, fun, args} ->
        case apply(mod, fun, [assertion, digest | args]) do
          :ok -> :ok
          _ -> {:error, :duplicate}
        end
    end
  end

  defp callback(key) do
    case Application.get_env(:samly, key) do
      nil ->
        nil

      {mod, fun, args} = mfa when is_atom(mod) and is_atom(fun) and is_list(args) ->
        mfa

      other ->
        raise ArgumentError,
              "config :samly, #{inspect(key)} must be {module, function, args}, got: " <>
                inspect(other)
    end
  end

  def decode_idp_signout_resp(sp, saml_encoding, saml_response) do
    resp_ns = [
      {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
      {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"},
      {~c"ds", ~c"http://www.w3.org/2000/09/xmldsig#"}
    ]

    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_response),
         nodes when is_list(nodes) and length(nodes) == 1 <-
           :xmerl_xpath.string(~c"/samlp:LogoutResponse", xml_frag, [{:namespace, resp_ns}]) do
      :esaml_sp.validate_logout_response(xml_frag, sp)
    else
      _ -> {:error, :invalid_request}
    end
  end

  def decode_idp_signout_req(sp, saml_encoding, saml_request) do
    req_ns = [
      {~c"samlp", ~c"urn:oasis:names:tc:SAML:2.0:protocol"},
      {~c"saml", ~c"urn:oasis:names:tc:SAML:2.0:assertion"}
    ]

    with {:ok, xml_frag} <- decode_saml_payload(saml_encoding, saml_request),
         nodes when is_list(nodes) and length(nodes) == 1 <-
           :xmerl_xpath.string(~c"/samlp:LogoutRequest", xml_frag, [{:namespace, req_ns}]) do
      :esaml_sp.validate_logout_request(xml_frag, sp)
    else
      _ -> {:error, :invalid_request}
    end
  end

  defp decode_saml_payload(saml_encoding, saml_payload) do
    try do
      # The esaml fork returns {:error, reason} for a payload that it refuses,
      # for example a payload with a DOCTYPE.
      case :esaml_binding.decode_response(saml_encoding, saml_payload) do
        {:error, reason} -> {:error, {:invalid_response, reason}}
        xml -> {:ok, xml}
      end
    rescue
      error -> {:error, {:invalid_response, "#{inspect(error)}"}}
    end
  end
end
