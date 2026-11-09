defmodule SamlyAuthHandlerTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import SweetXml, only: [sigil_x: 2, xpath: 2]
  import Samly.TestSAML

  setup do
    on_exit(&reset_env/0)
    %{idp: setup_provider(%{signed_assertion_in_resp: false, signed_envelopes_in_resp: false})}
  end

  test "stores the AuthnRequest ID in the session", %{idp: idp} do
    conn = send_signin(idp)

    assert conn.status == 200
    request_id = get_session(conn, "authn_request_id")
    assert is_binary(request_id) and request_id != ""

    request_xml = conn.resp_body |> form_value("SAMLRequest") |> Base.decode64!()
    assert xpath(request_xml, ~x"/*/@ID"s) == request_id
  end

  test "a response to the stored AuthnRequest signs the user in", %{idp: idp} do
    signin_conn = send_signin(idp)
    session = get_session(signin_conn)
    request_id = session["authn_request_id"]
    relay_state = signin_conn.resp_body |> form_value("RelayState")

    conn = post_consume(response_xml(in_response_to: request_id), session, relay_state)

    assert conn.status == 302
    assert get_resp_header(conn, "location") == ["/home"]
    assert get_session(conn, "authn_request_id") == nil
  end
end
