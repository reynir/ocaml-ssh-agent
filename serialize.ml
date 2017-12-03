open Types

let with_faraday (f : Faraday.t -> unit) : string =
  let buf = Faraday.create 1024 in
  f buf;
  Faraday.serialize_to_string buf

let write_ssh_agent t n =
  let n = Protocol_number.ssh_agent_to_int n in
  Faraday.write_uint8 t n

let write_ssh_agent_request t (type a) (req : a ssh_agent_request) =
  let message = with_faraday (fun t ->
      match req with
      | Ssh_agentc_request_identities ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_REQUEST_IDENTITIES)
      | Ssh_agentc_sign_request (pubkey, data, flags) ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_SIGN_REQUEST);
        Wire.write_string t (with_faraday (fun t -> Pubkey.write_pubkey t pubkey));
        Wire.write_string t data;
        Protocol_number.write_sign_flags t flags
      | Ssh_agentc_add_identity { privkey; key_comment } ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_ADD_IDENTITY);
        Privkey.write_privkey t privkey;
        Wire.write_string t key_comment
      | Ssh_agentc_remove_identity pubkey ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_REMOVE_IDENTITY);
        Wire.write_string t (with_faraday (fun t -> Pubkey.write_pubkey t pubkey))
      | Ssh_agentc_remove_all_identities ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_REMOVE_ALL_IDENTITIES)
      | Ssh_agentc_add_smartcard_key { smartcard_id; smartcard_pin } ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_ADD_SMARTCARD_KEY);
        Wire.write_string t smartcard_id;
        Wire.write_string t smartcard_pin
      | Ssh_agentc_remove_smartcard_key { smartcard_reader_id; smartcard_reader_pin } ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_REMOVE_SMARTCARD_KEY);
        Wire.write_string t smartcard_reader_id;
        Wire.write_string t smartcard_reader_pin
      | Ssh_agentc_lock passphrase ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_LOCK);
        Faraday.write_string t passphrase
      | Ssh_agentc_unlock passphrase ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_UNLOCK);
        Faraday.write_string t passphrase
      | Ssh_agentc_add_id_constrained { key_type; key_contents;
                                        key_comment; key_constraints } ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_ADD_ID_CONSTRAINED);
        Wire.write_string t key_type;
        Faraday.write_string t key_contents;
        Wire.write_string t key_comment;
        Protocol_number.write_key_constraints t key_constraints
      | Ssh_agentc_add_smartcard_key_constrained { smartcard_id; smartcard_pin;
                                                   smartcard_constraints } ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED);
        Wire.write_string t smartcard_id;
        Wire.write_string t smartcard_pin;
        Protocol_number.write_key_constraints t smartcard_constraints
      | Ssh_agentc_extension _ ->
        failwith "Not implemented"
    ) in
  Wire.write_uint32 t (Int32.of_int (String.length message));
  Faraday.write_string t message
