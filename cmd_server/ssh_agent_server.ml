type identity = { privkey : Ssh_agent.Privkey.t; comment : string }

let pubkey_identity_of_identity { privkey; comment } =
  match privkey with
  | Ssh_agent.Privkey.Ssh_rsa key ->
    { Ssh_agent.pubkey = Ssh_agent.Pubkey.Ssh_rsa (Nocrypto.Rsa.pub_of_priv key);
      comment }
  | Ssh_agent.Privkey.Ssh_dss key ->
    { Ssh_agent.pubkey = Ssh_agent.Pubkey.Ssh_dss (Nocrypto.Dsa.pub_of_priv key); comment }
  | Ssh_agent.Privkey.Blob _ ->
    failwith "Can't handle this key type"

let identities : identity list ref = ref []

let handler (type req_type) (request : req_type Ssh_agent.ssh_agent_request)
  : req_type Ssh_agent.ssh_agent_response =
  let open Ssh_agent in
  match request with
   | Ssh_agentc_request_identities ->
     let identities = List.map pubkey_identity_of_identity !identities in
     Ssh_agent_identities_answer identities
   | Ssh_agentc_sign_request (pubkey,blob,flags) ->
     begin match List.find (fun ({ privkey; comment } as id) ->
         (pubkey_identity_of_identity id).pubkey = pubkey)
         !identities with
     | { privkey; comment } ->
       Printf.printf "Signing using key %s\n%!" comment;
       let () = Sexplib.Sexp.List (List.map Ssh_agent.sexp_of_sign_flag flags)
                |> Sexplib.Sexp.to_string
                |> print_endline in
       let signature = Ssh_agent.sign privkey flags blob in
       Ssh_agent_sign_response signature
     | exception Not_found ->
       Ssh_agent_failure
     end
   | Ssh_agentc_add_identity { privkey; key_comment } ->
     identities := { privkey; comment = key_comment } :: !identities;
     Ssh_agent_success
   | Ssh_agentc_remove_identity _ ->
     Ssh_agent_failure
   | Ssh_agentc_remove_all_identities ->
     print_endline "Removing all identities";
     identities := [];
     Ssh_agent_success
   | Ssh_agentc_add_smartcard_key _ ->
     Ssh_agent_failure
   | Ssh_agentc_remove_smartcard_key _ ->
     Ssh_agent_failure
   | Ssh_agentc_lock _ ->
     Ssh_agent_failure
   | Ssh_agentc_unlock _ ->
     Ssh_agent_failure
   | Ssh_agentc_add_id_constrained _ ->
     Ssh_agent_failure
   | Ssh_agentc_add_smartcard_key_constrained _ ->
     Ssh_agent_failure
   | Ssh_agentc_extension _ -> 
     Ssh_agent_failure

let main () =
  let () = Nocrypto_entropy_unix.initialize () in
  let fd = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let sockaddr = Unix.ADDR_UNIX "ocaml-ssh-agent.socket" in
  let () = Unix.bind fd sockaddr in
  let () = Unix.listen fd 3 in
  Ssh_agent_unix.accept fd { handle = handler }

let () = main ()
