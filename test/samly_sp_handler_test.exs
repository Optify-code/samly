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

      conn = post_consume(response_xml(in_response_to: "req-1"))

      assert conn.status == 302

      assert_received {:duplicate_check,
                       %Samly.Assertion{
                         idp_id: "idp1",
                         issuer: "urn:test:idp",
                         subject: %{name: "user@example.com"}
                       }, digest}

      assert is_binary(digest) and byte_size(digest) == 32
    end

    test "refuses the response when the duplicate check does not return :ok" do
      Application.put_env(
        :samly,
        :duplicate_check,
        {DupCheck, :check, [self(), {:error, :replayed}]}
      )

      conn = post_consume(response_xml(in_response_to: "req-1"))

      assert conn.status == 403
      assert conn.resp_body == "access_denied :duplicate"
      assert get_session(conn, "samly_assertion_key") == nil
    end

    test "raises on an invalid duplicate check setting", %{idp: idp} do
      Application.put_env(:samly, :duplicate_check, :bad)
      xml = response_xml(in_response_to: "req-1")

      assert_raise ArgumentError, ~r/:duplicate_check/, fn ->
        Samly.Helper.decode_idp_auth_resp(idp.esaml_sp_rec, nil, Base.encode64(xml), "idp1")
      end
    end
  end
end
