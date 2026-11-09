defmodule SamlySPHandlerTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Samly.TestSAML

  defmodule DupCheck do
    def check(assertion, digest, pid, result) do
      send(pid, {:duplicate_check, assertion, digest})
      result
    end
  end

  # A shared store with an atomic claim, as the README advises.
  defmodule Claim do
    def check(_assertion, digest, table) do
      if :ets.insert_new(table, {digest}), do: :ok, else: {:error, :claimed}
    end

    def release(_assertion, digest, table) do
      :ets.delete(table, digest)
    end
  end

  defp claim_check do
    table = :ets.new(:claims, [:set, :public])
    Application.put_env(:samly, :duplicate_check, {Claim, :check, [table]})
    Application.put_env(:samly, :duplicate_release, {Claim, :release, [table]})
  end

  # Another node has its own table of used request IDs.
  defp on_other_node do
    :ets.delete_all_objects(:samly_used_request_ids)
  end

  # A pre-session pipeline that halts while the process has :halt_pipeline set.
  defmodule HaltPipeline do
    def call(conn, _opts) do
      if Process.get(:halt_pipeline),
        do: conn |> Plug.Conn.send_resp(403, "pipeline_refused") |> Plug.Conn.halt(),
        else: conn
    end
  end

  # A state store that raises while the process has :fail_store set.
  defmodule FailingStore do
    @behaviour Samly.State.Store
    def init(opts), do: Samly.State.Session.init(opts)
    def get_assertion(conn, key, opts), do: Samly.State.Session.get_assertion(conn, key, opts)

    def put_assertion(conn, key, assertion, opts) do
      if Process.get(:fail_store), do: raise("store down")
      Samly.State.Session.put_assertion(conn, key, assertion, opts)
    end

    def delete_assertion(conn, key, opts),
      do: Samly.State.Session.delete_assertion(conn, key, opts)
  end

  @unsigned %{signed_assertion_in_resp: false, signed_envelopes_in_resp: false}

  setup do
    on_exit(&reset_env/0)
    :ok
  end

  describe "duplicate check" do
    setup do
      %{idp: setup_provider(@unsigned)}
    end

    test "accepts every assertion when no duplicate check is set" do
      conn = post_consume(response_xml(in_response_to: "req-1"))

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["/home"]
      assert get_session(conn, "samly_assertion_key") == {"idp1", "user@example.com"}
    end

    test "passes the assertion with its IdP id and the digest to the duplicate check" do
      Application.put_env(:samly, :duplicate_check, {DupCheck, :check, [self(), :ok]})
      xml = response_xml(in_response_to: "req-1")

      conn = post_consume(xml)

      assert conn.status == 302

      assert_received {:duplicate_check,
                       %Samly.Assertion{
                         idp_id: "idp1",
                         issuer: "urn:test:idp",
                         subject: %{name: "user@example.com", in_response_to: "req-1"}
                       } = assertion, digest}

      assert byte_size(digest) == 32
      assert digest == Samly.Helper.assertion_digest(assertion)
      assert digest == digest_of(xml)

      refute digest ==
               digest_of(response_xml(in_response_to: "req-1", name_id: "other@example.com"))
    end

    test "gives the same digest when an unsigned Response attribute changes", %{idp: idp} do
      xml = response_xml(in_response_to: "req-1")
      changed = String.replace(xml, ~s(ID="_r1"), ~s(ID="_r2"))
      assert changed != xml

      assert digest_of(changed, idp) == digest_of(xml, idp)
    end

    test "refuses a replayed response with a changed unsigned Response attribute" do
      claim_check()
      xml = response_xml(in_response_to: "req-1")

      assert post_consume(xml).status == 302

      on_other_node()
      conn = post_consume(String.replace(xml, ~s(ID="_r1"), ~s(ID="_r2")))

      assert conn.status == 403
      assert conn.resp_body == "access_denied :duplicate"
    end

    test "refuses the response when the duplicate check does not return :ok" do
      for result <- [{:error, :replayed}, :error, false, nil, "ok", {:ok, :claimed}] do
        Application.put_env(:samly, :duplicate_check, {DupCheck, :check, [self(), result]})

        conn = post_consume(response_xml(in_response_to: "req-1"))

        assert_received {:duplicate_check, _, _}
        assert conn.status == 403, "accepted #{inspect(result)}"
        assert conn.resp_body == "access_denied :duplicate"
        assert get_session(conn, "samly_assertion_key") == nil
        assert get_session(conn, "authn_request_id") == "req-1"
      end
    end

    test "does not call the duplicate check for a response that samly refuses" do
      Application.put_env(:samly, :duplicate_check, {DupCheck, :check, [self(), :ok]})
      xml = response_xml(in_response_to: "req-1")

      conn = post_consume(xml, default_session(), "wrong-relay-state")

      assert conn.status == 403
      assert conn.resp_body == "access_denied :invalid_relay_state"
      refute_received {:duplicate_check, _, _}

      claim_check()
      assert post_consume(xml, default_session(), "wrong-relay-state").status == 403
      assert post_consume(xml).status == 302
    end

    test "refuses a replayed response that the duplicate check claimed" do
      claim_check()
      xml = response_xml(in_response_to: "req-1")

      assert post_consume(xml).status == 302

      on_other_node()
      conn = post_consume(xml)

      assert conn.status == 403
      assert conn.resp_body == "access_denied :duplicate"
    end

    test "accepts a retry of a response after the pre-session pipeline halts" do
      claim_check()
      setup_provider(Map.put(@unsigned, :pre_session_create_pipeline, HaltPipeline))
      xml = response_xml(in_response_to: "req-1")

      Process.put(:halt_pipeline, true)
      halted = post_consume(xml)

      assert halted.status == 403
      assert halted.resp_body == "pipeline_refused"

      Process.delete(:halt_pipeline)
      conn = post_consume(xml)

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["/home"]
    end

    test "accepts a retry of a response after the state store fails" do
      claim_check()
      Samly.State.init(FailingStore)
      xml = response_xml(in_response_to: "req-1")

      Process.put(:fail_store, true)

      error = assert_raise Plug.Conn.WrapperError, fn -> post_consume(xml) end
      assert %RuntimeError{message: "store down"} = error.reason

      Process.delete(:fail_store)
      conn = post_consume(xml)

      assert conn.status == 302
      assert get_session(conn, "samly_assertion_key") == {"idp1", "user@example.com"}
    end

    test "raises on an invalid duplicate check setting" do
      Application.put_env(:samly, :duplicate_check, :bad)
      assertion = %Samly.Assertion{idp_id: "idp1"}

      assert_raise ArgumentError, ~r/:duplicate_check/, fn ->
        Samly.Helper.check_duplicate(assertion, <<0::256>>)
      end
    end
  end

  describe "SP-initiated InResponseTo" do
    setup do
      %{idp: setup_provider(@unsigned)}
    end

    test "accepts a response whose InResponseTo matches the stored request ID" do
      conn = post_consume(response_xml(in_response_to: "req-1"))

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["/home"]
    end

    test "refuses a response whose InResponseTo differs from the stored request ID" do
      conn = post_consume(response_xml(in_response_to: "req-2"))

      assert conn.status == 403
      assert conn.resp_body == "access_denied :invalid_in_response_to"
      assert get_session(conn, "authn_request_id") == "req-1"
    end

    test "refuses a response when no request ID is stored" do
      session = Map.delete(default_session(), "authn_request_id")
      conn = post_consume(response_xml(in_response_to: "req-1"), session)

      assert conn.status == 403
      assert conn.resp_body == "access_denied :invalid_in_response_to"
    end

    test "deletes the stored request ID after a matching response" do
      conn = post_consume(response_xml(in_response_to: "req-1"))

      assert conn.status == 302
      assert get_session(conn, "authn_request_id") == nil
    end

    test "refuses a response posted again with the original session" do
      xml = response_xml(in_response_to: "req-1")

      assert post_consume(xml).status == 302

      # The original session still holds the ID, as an old session cookie does.
      replay = post_consume(xml, default_session())

      assert replay.status == 403
      assert replay.resp_body == "access_denied :invalid_in_response_to"
    end

    test "accepts only one of two concurrent responses to the same request ID" do
      xml = response_xml(in_response_to: "req-1")

      results =
        1..2
        |> Enum.map(fn _ ->
          Task.async(fn ->
            conn = post_consume(xml)
            {conn.status, conn.resp_body}
          end)
        end)
        |> Enum.map(&Task.await/1)
        |> Enum.sort()

      assert [{302, _}, {403, "access_denied :invalid_in_response_to"}] = results
    end

    test "accepts a new request ID after a request ID is used" do
      assert post_consume(response_xml(in_response_to: "req-1")).status == 302

      session = Map.put(default_session(), "authn_request_id", "req-2")
      assert post_consume(response_xml(in_response_to: "req-2"), session).status == 302
    end

    test "refuses the same response posted again in the same session" do
      xml = response_xml(in_response_to: "req-1")
      conn1 = post_consume(xml)
      assert conn1.status == 302

      conn2 = post_consume(xml, get_session(conn1))

      assert conn2.status == 403
      assert conn2.resp_body == "access_denied :invalid_in_response_to"
    end
  end

  describe "signed assertions" do
    setup do
      %{idp: setup_provider(%{signed_envelopes_in_resp: false})}
    end

    test "accepts a signed assertion whose InResponseTo matches the stored request ID" do
      conn = post_consume(response_xml(in_response_to: "req-1", sign: true))

      assert conn.status == 302
      assert get_resp_header(conn, "location") == ["/home"]
    end

    test "refuses a signed assertion whose InResponseTo differs from the stored request ID" do
      conn = post_consume(response_xml(in_response_to: "req-2", sign: true))

      assert conn.status == 403
      assert conn.resp_body == "access_denied :invalid_in_response_to"
    end
  end

  describe "unsolicited responses" do
    test "refuses a response without InResponseTo when IdP-initiated sign-in is off" do
      setup_provider(@unsigned)

      conn = post_consume(response_xml(in_response_to: nil))

      assert conn.status == 403
      assert conn.resp_body == "access_denied :idp_first_flow_not_allowed"
      assert get_session(conn, "samly_assertion_key") == nil
    end

    test "restarts an SP-initiated sign-in for a response without InResponseTo" do
      setup_provider(Map.put(@unsigned, :allow_idp_initiated_flow, true))

      conn = post_consume(response_xml(in_response_to: nil), default_session(), "/landing")

      assert conn.status == 302

      assert get_resp_header(conn, "location") == [
               "/auth/signin/idp1?target_url=%252Flanding"
             ]

      assert get_session(conn, "samly_assertion_key") == nil
      assert get_session(conn, "samly_restarted_idp") == "idp1"
    end

    test "does not spend the assertion when it restarts the sign-in" do
      setup_provider(Map.put(@unsigned, :allow_idp_initiated_flow, true))
      claim_check()
      xml = response_xml(in_response_to: nil)

      conn = post_consume(xml, default_session(), "/landing")
      assert conn.status == 302

      pending = post_consume(response_xml(in_response_to: "req-1"), get_session(conn))
      assert pending.status == 302
      assert get_resp_header(pending, "location") == ["/home"]
      assert get_session(pending, "samly_restarted_idp") == nil
    end

    test "refuses a second unsolicited response in a row" do
      setup_provider(Map.put(@unsigned, :allow_idp_initiated_flow, true))

      first = post_consume(response_xml(in_response_to: nil), default_session(), "/landing")
      assert first.status == 302

      second = post_consume(response_xml(in_response_to: nil), get_session(first), "/landing")

      assert second.status == 403
      assert second.resp_body == "access_denied :unsolicited_response"
      assert get_session(second, "samly_restarted_idp") == nil
    end

    test "restarts to / when RelayState is empty or not a local path" do
      setup_provider(Map.put(@unsigned, :allow_idp_initiated_flow, true))

      for relay_state <- ["", "https://evil.example/x", "//evil.example/x", "/\\evil.example"] do
        conn = post_consume(response_xml(in_response_to: nil), %{}, relay_state)

        assert get_resp_header(conn, "location") == ["/auth/signin/idp1?target_url=%252F"],
               "RelayState #{inspect(relay_state)}"
      end
    end

    test "keeps the allowed_target_urls check" do
      setup_provider(
        @unsigned
        |> Map.put(:allow_idp_initiated_flow, true)
        |> Map.put(:allowed_target_urls, ["https://app.example/in"])
      )

      allowed = post_consume(response_xml(in_response_to: nil), %{}, "https://app.example/in")

      assert get_resp_header(allowed, "location") == [
               "/auth/signin/idp1?target_url=https%253A%252F%252Fapp.example%252Fin"
             ]

      refused = post_consume(response_xml(in_response_to: nil), %{}, "/other")
      assert refused.status == 403
      assert refused.resp_body == "access_denied :invalid_target_url"
    end

    test "builds the sign-in path from the mount point" do
      setup_provider(Map.put(@unsigned, :allow_idp_initiated_flow, true))

      conn =
        Plug.Test.conn(:post, "/saml2/sp/consume/idp1", %{
          "SAMLResponse" => Base.encode64(response_xml(in_response_to: nil)),
          "RelayState" => "/landing"
        })
        |> Plug.Test.init_test_session(%{})
        |> Map.merge(%{script_name: ["saml2"], path_info: ["sp", "consume", "idp1"]})
        |> Samly.Router.call(Samly.Router.init([]))

      assert get_resp_header(conn, "location") == [
               "/saml2/auth/signin/idp1?target_url=%252Flanding"
             ]
    end
  end

  describe "esaml refusals" do
    setup do
      %{idp: setup_provider(@unsigned)}
    end

    test "answers 403 for a LogoutResponse with a DOCTYPE" do
      # Without the DOCTYPE, samly accepts the same LogoutResponse.
      assert post_logout("SAMLResponse", logout_response_xml()).status == 302

      conn = post_logout("SAMLResponse", logout_response_xml(doctype: true))

      assert conn.status == 403
      assert String.starts_with?(conn.resp_body, "invalid_request")
    end

    test "answers a denied LogoutResponse for a LogoutRequest with a DOCTYPE" do
      # Without the DOCTYPE, samly decodes and validates the same signed LogoutRequest.
      # It logs no error. It denies the request only because no user is signed in.
      assert ExUnit.CaptureLog.capture_log(fn ->
               assert post_logout("SAMLRequest", logout_request_xml()).status == 200
             end) == ""

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          conn = post_logout("SAMLRequest", logout_request_xml(doctype: true))
          send(self(), {:conn, conn})
        end)

      assert_received {:conn, conn}
      assert log =~ "invalid_request"
      assert conn.status == 200
      assert [content_type] = get_resp_header(conn, "content-type")
      assert content_type =~ "text/html"

      logout_response = conn.resp_body |> form_value("SAMLResponse") |> Base.decode64!()
      assert logout_response =~ "LogoutResponse"
      assert logout_response =~ "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
    end

    test "answers 403 for a SAMLResponse with a DOCTYPE" do
      conn = post_consume(doctype_xml())

      assert conn.status == 403
      assert String.starts_with?(conn.resp_body, "access_denied")
    end
  end

  defp digest_of(xml, idp \\ Samly.Helper.get_idp("idp1")) do
    {:ok, _assertion, digest} =
      Samly.Helper.decode_idp_auth_resp(idp.esaml_sp_rec, nil, Base.encode64(xml))

    digest
  end
end
