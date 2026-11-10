defmodule Samly.SPHandler do
  @moduledoc false

  require Logger
  import Plug.Conn
  alias Plug.Conn
  require Samly.Esaml
  alias Samly.{Assertion, Esaml, Helper, IdpData, State, Subject}

  import Samly.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 5, redirect: 3]

  @restart_key "samly_restarted_idp"

  def send_metadata(conn) do
    %IdpData{} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)
    metadata = Helper.sp_metadata(sp)

    conn
    |> put_resp_header("content-type", "text/xml")
    |> send_resp(200, metadata)

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  def consume_signin_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{pre_session_create_pipeline: pipeline, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()

    with {:ok, assertion, digest} <-
           Helper.decode_idp_auth_resp(sp, saml_encoding, saml_response),
         :ok <- validate_authresp(conn, assertion, relay_state),
         assertion = %Assertion{assertion | idp_id: idp_id},
         :ok <- Helper.claim_assertion(assertion, digest),
         {:ok, conn, assertion_key} <- accept_or_release(conn, assertion, digest, pipeline) do
      target_url = auth_target_url(conn)

      conn
      |> configure_session(renew: true)
      |> put_session("samly_assertion_key", assertion_key)
      |> redirect(302, target_url)
    else
      {:halted, conn} -> conn
      {:restart, target_url} -> restart_signin(conn, idp_id, target_url)
      {:error, reason} -> conn |> send_resp(403, "access_denied #{inspect(reason)}")
      _ -> conn |> send_resp(403, "access_denied")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # An unsolicited response never signs in. Anyone can post their own valid
  # assertion to another user's browser. The browser starts an SP-initiated
  # sign-in at the same IdP instead. The IdP answers for the user that holds
  # the IdP session, so a user from the IdP portal signs in after one more
  # redirect. A second unsolicited response in a row is refused, so an IdP
  # that never sets InResponseTo cannot cause a redirect loop.
  defp restart_signin(conn, idp_id, target_url) do
    if get_session(conn, @restart_key) == idp_id do
      conn
      |> delete_session(@restart_key)
      |> send_resp(403, "access_denied #{inspect(:unsolicited_response)}")
    else
      query = URI.encode_query(%{"target_url" => URI.encode_www_form(target_url)})

      conn
      |> put_session(@restart_key, idp_id)
      |> redirect(302, signin_path(conn, idp_id) <> "?" <> query)
    end
  end

  # The SP router is mounted at "<prefix>/sp" and the auth router at "<prefix>/auth".
  defp signin_path(conn, idp_id) do
    prefix = conn.script_name |> Enum.drop(-1) |> Enum.map(&("/" <> &1)) |> Enum.join()

    if Application.get_env(:samly, :idp_id_from) == :subdomain,
      do: prefix <> "/auth/signin",
      else: prefix <> "/auth/signin/" <> URI.encode(idp_id, &URI.char_unreserved?/1)
  end

  # Runs the pre-session pipeline and stores the assertion.
  # A halt means the pipeline refused the sign-in and wrote no session. Then
  # samly releases the claims, so a later retry is not refused as a duplicate.
  # A raise from the pipeline or the state store keeps the claims (fail
  # closed). samly cannot know whether the pipeline already signed the user in.
  defp accept_or_release(conn, assertion, digest, pipeline) do
    %Assertion{idp_id: idp_id} = assertion

    conn =
      conn
      |> consume_authn_request_id(assertion)
      |> put_private(:samly_assertion, assertion)
      |> pipethrough(pipeline)

    if conn.halted do
      Helper.release_assertion(assertion, digest)
      {:halted, conn}
    else
      computed = conn.private[:samly_assertion].computed
      assertion = %Assertion{assertion | computed: computed, idp_id: idp_id}
      assertion_key = {idp_id, assertion.subject.name}
      {:ok, State.put_assertion(conn, assertion_key, assertion), assertion_key}
    end
  end

  # IDP-initiated flow auth response
  @spec validate_authresp(Conn.t(), Assertion.t(), binary) ::
          :ok | {:restart, binary} | {:error, atom}
  defp validate_authresp(conn, %{subject: %{in_response_to: ""}}, relay_state) do
    idp_data = conn.private[:samly_idp]

    cond do
      not idp_data.allow_idp_initiated_flow ->
        {:error, :idp_first_flow_not_allowed}

      relay_state in [nil, ""] ->
        {:restart, "/"}

      is_list(idp_data.allowed_target_urls) ->
        if relay_state in idp_data.allowed_target_urls,
          do: {:restart, relay_state},
          else: {:error, :invalid_target_url}

      local_path?(relay_state) ->
        {:restart, relay_state}

      true ->
        {:restart, "/"}
    end
  end

  # SP-initiated flow auth response
  defp validate_authresp(conn, %{subject: %{in_response_to: in_response_to}}, relay_state) do
    %IdpData{id: idp_id} = conn.private[:samly_idp]
    rs_in_session = get_session(conn, "relay_state")
    idp_id_in_session = get_session(conn, "idp_id")
    url_in_session = get_session(conn, "target_url")
    request_id_in_session = get_session(conn, "authn_request_id")

    cond do
      rs_in_session == nil || rs_in_session != relay_state ->
        {:error, :invalid_relay_state}

      idp_id_in_session == nil || idp_id_in_session != idp_id ->
        {:error, :invalid_idp_id}

      url_in_session == nil ->
        {:error, :invalid_target_url}

      request_id_in_session == nil || request_id_in_session != in_response_to ->
        {:error, :invalid_in_response_to}

      true ->
        :ok
    end
  end

  # RelayState is not signed. Without an allowed_target_urls list, only a path
  # on this site is kept.
  defp local_path?("/" <> rest) do
    not String.starts_with?(rest, ["/", "\\"]) and
      not String.contains?(rest, ["\\", "\r", "\n", "\t"]) and
      match?(%URI{scheme: nil, host: nil}, URI.parse("/" <> rest))
  end

  defp local_path?(_target), do: false

  defp consume_authn_request_id(conn, _assertion) do
    conn
    |> delete_session("authn_request_id")
    |> delete_session(@restart_key)
  end

  defp pipethrough(conn, nil), do: conn

  defp pipethrough(conn, pipeline) do
    pipeline.call(conn, [])
  end

  defp auth_target_url(conn) do
    get_session(conn, "target_url") || "/"
  end

  def handle_logout_response(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: _idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_response = conn.body_params["SAMLResponse"]
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()

    with {:ok, _payload} <- Helper.decode_idp_signout_resp(sp, saml_encoding, saml_response),
         ^relay_state when relay_state != nil <- get_session(conn, "relay_state"),
         ^idp_id <- get_session(conn, "idp_id"),
         target_url when target_url != nil <- get_session(conn, "target_url") do
      conn
      |> configure_session(drop: true)
      |> redirect(302, target_url)
    else
      error -> conn |> send_resp(403, "invalid_request #{inspect(error)}")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  # non-ui logout request from IDP
  def handle_logout_request(conn) do
    %IdpData{id: idp_id} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    saml_encoding = conn.body_params["SAMLEncoding"]
    saml_request = conn.body_params["SAMLRequest"]
    relay_state = conn.body_params["RelayState"] |> safe_decode_www_form()

    with {:ok, payload} <- Helper.decode_idp_signout_req(sp, saml_encoding, saml_request) do
      Esaml.esaml_logoutreq(name: nameid, issuer: _issuer) = payload
      assertion_key = {idp_id, nameid}

      {conn, return_status} =
        case State.get_assertion(conn, assertion_key) do
          %Assertion{idp_id: ^idp_id, subject: %Subject{name: ^nameid}} ->
            conn = State.delete_assertion(conn, assertion_key)
            {conn, :success}

          _ ->
            {conn, :denied}
        end

      {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, return_status)

      conn
      |> configure_session(drop: true)
      |> send_saml_request(idp_signout_url, idp.use_redirect_for_req, resp_xml_frag, relay_state)
    else
      error ->
        Logger.error("#{inspect(error)}")
        {idp_signout_url, resp_xml_frag} = Helper.gen_idp_signout_resp(sp, idp_rec, :denied)

        conn
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_req,
          resp_xml_frag,
          relay_state
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  defp safe_decode_www_form(nil), do: ""
  defp safe_decode_www_form(data), do: URI.decode_www_form(data)
end
