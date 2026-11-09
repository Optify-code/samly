defmodule Samly.UsedRequestIds do
  @moduledoc false
  # Records the AuthnRequest IDs that SP-initiated responses used on this node.
  # :ets.insert_new/2 makes each claim atomic, so one ID signs in one time only,
  # even with two requests at the same time or with an old session cookie.
  # The table is local to the node. In a cluster, the duplicate check gives
  # single use across nodes (see the README).

  @table :samly_used_request_ids

  # Clock skew in seconds that the entry keeps after the assertion is stale.
  @skew 60

  # Creates the table. Samly.Provider.init/1 calls it, so the Provider owns it.
  def init do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:set, :public, :named_table])
    end

    :ok
  end

  @spec claim(binary, binary, integer) :: :ok | {:error, :invalid_in_response_to}
  def claim(idp_id, request_id, expires_at) do
    now = System.os_time(:second)
    :ets.select_delete(@table, [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}])

    if :ets.insert_new(@table, {{idp_id, request_id}, expires_at + @skew}) do
      :ok
    else
      {:error, :invalid_in_response_to}
    end
  end

  @spec release(binary, binary) :: :ok
  def release(idp_id, request_id) do
    :ets.delete(@table, {idp_id, request_id})
    :ok
  end
end
