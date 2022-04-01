open Ssh_agent

type identity = {
  privkey : Privkey.t;
  comment : string;
}

let state : identity list ref = ref []

let pubkey_of_privkey = function
  | Privkey.Ssh_rsa priv ->
    Ok (Pubkey.Ssh_rsa (Mirage_crypto_pk.Rsa.pub_of_priv priv))
  | Privkey.Ssh_rsa_cert (_priv, cert) ->
    Ok (Pubkey.Ssh_rsa_cert cert)
  | Privkey.Ssh_dss priv ->
    Ok (Pubkey.Ssh_dss (Mirage_crypto_pk.Dsa.pub_of_priv priv))
  | Privkey.Ssh_ed25519 priv ->
    Ok (Pubkey.Ssh_ed25519 (Mirage_crypto_ec.Ed25519.pub_of_priv priv))
  | Privkey.Blob _ ->
    Error "Unsupported key"

let is_pubkey pubkey { privkey; _ } =
  pubkey_of_privkey privkey
  |> Result.fold ~error:(Fun.const false) ~ok:(Pubkey.equal pubkey)

let handle (type req) (request : req ssh_agent_request) : req ssh_agent_response =
  match request with
  | Ssh_agentc_request_identities ->
    let identities =
      List.filter_map (fun { privkey; comment } ->
          Result.to_option (pubkey_of_privkey privkey)
          |> Option.map (fun pubkey -> { comment; pubkey }))
        !state
    in
    Ssh_agent_identities_answer identities
  | Ssh_agentc_add_identity { privkey; key_comment } ->
    state := { privkey; comment = key_comment } :: !state;
    Ssh_agent_success
  | Ssh_agentc_sign_request (pubkey, to_be_signed, flags) ->
    let privkey = List.find_opt (is_pubkey pubkey) !state in
    Option.fold privkey
      ~none:Ssh_agent_failure
      ~some:(fun { privkey; _ } ->
          Ssh_agent_sign_response (Ssh_agent.sign privkey flags to_be_signed))
  | Ssh_agentc_remove_identity pubkey ->
    state := List.filter (is_pubkey pubkey) !state;
    Ssh_agent_success
  | Ssh_agentc_remove_all_identities ->
    state := [];
    Ssh_agent_success
  | Ssh_agentc_add_smartcard_key _ -> Ssh_agent_failure
  | Ssh_agentc_remove_smartcard_key _ -> Ssh_agent_failure
  | Ssh_agentc_lock _ -> Ssh_agent_failure
  | Ssh_agentc_unlock _ -> Ssh_agent_failure
  | Ssh_agentc_add_id_constrained _ -> Ssh_agent_failure
  | Ssh_agentc_add_smartcard_key_constrained _ -> Ssh_agent_failure
  | Ssh_agentc_extension _ -> Ssh_agent_failure

let accept (ic, oc) =
  let rec loop = function
    | Angstrom.Buffered.Done (u, Any_request req) ->
      let resp = handle req in
      let buf = Faraday.create 4096 in
      Serialize.write_ssh_agent_response buf resp;
      output_string oc (Faraday.serialize_to_string buf);
      flush oc;
      let s = Angstrom.Buffered.parse Parse.ssh_agentc_message in
      let s =
        Angstrom.Buffered.feed s
          (`Bigstring (Bigarray.Array1.sub u.buf u.off u.len))
      in
      loop s
    | Angstrom.Buffered.Partial s ->
      let buf = Bytes.create 1024 in
      let r = input ic buf 0 1024 in
      let s = s (if r = 0 then `Eof else `String (Bytes.sub_string buf 0 r)) in
      loop s
    | Angstrom.Buffered.Fail (u, marks, err) ->
      if u.len > 0 then
        prerr_endline (String.concat " > " marks ^ ": " ^ err);
  in
  loop (Angstrom.Buffered.parse Parse.ssh_agentc_message);
  close_in_noerr ic;
  close_out_noerr oc

let () =
  let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  Unix.bind sock (Unix.ADDR_UNIX "ocaml-ssh-agent.sock");
  Unix.listen sock 1;
  while true do
    let client, _client_addr = Unix.accept sock in
    let ic = Unix.in_channel_of_descr client
    and oc = Unix.out_channel_of_descr client in
    accept (ic, oc)
  done

