
module Request : Alcotest.TESTABLE with type t = Ssh_agent.any_ssh_agent_request = struct
  type t = Ssh_agent.any_ssh_agent_request
  let pp fmt (t : Ssh_agent.any_ssh_agent_request) =
    Fmt.string fmt "TODO:any_ssh_agent_request"
  let equal (x1 : t) (x2 : t) =
    let open Ssh_agent in
    match x1, x2 with
    | Any_request Ssh_agentc_request_identities,
      Any_request Ssh_agentc_request_identities ->
      true
    | Any_request (Ssh_agentc_sign_request (pubkey1,data1,flags1)),
      Any_request (Ssh_agentc_sign_request (pubkey2,data2,flags2)) ->
      pubkey1 = pubkey2
      && data1 = data2
      && flags1 = flags2
    (* FIXME: unordered list *)
    | Any_request (Ssh_agentc_add_identity { privkey = p1; key_comment = c1; }),
      Any_request (Ssh_agentc_add_identity { privkey = p2; key_comment = c2; }) ->
      p1 = p2 && c1 = c2
    | Any_request (Ssh_agentc_remove_identity id1),
      Any_request (Ssh_agentc_remove_identity id2) ->
      id1 = id2
    | Any_request Ssh_agentc_remove_all_identities,
      Any_request Ssh_agentc_remove_all_identities ->
      true
    | Any_request (Ssh_agentc_add_smartcard_key { smartcard_id = id1; smartcard_pin = pin1 }),
      Any_request (Ssh_agentc_add_smartcard_key { smartcard_id = id2; smartcard_pin = pin2 }) ->
      id1 = id2 && pin1 = pin2
    | Any_request (Ssh_agentc_remove_smartcard_key { smartcard_reader_id = id1; smartcard_reader_pin = pin1 }),
      Any_request (Ssh_agentc_remove_smartcard_key { smartcard_reader_id = id2; smartcard_reader_pin = pin2 }) ->
      id1 = id2 && pin1 = pin2
    | Any_request (Ssh_agentc_lock p1),
      Any_request (Ssh_agentc_lock p2) ->
      p1 = p2
    | Any_request (Ssh_agentc_unlock p1),
      Any_request (Ssh_agentc_unlock p2) ->
      p1 = p2
    | Any_request (Ssh_agentc_add_id_constrained
                     { privkey = p1; key_comment = c1; key_constraints = constraints1}),
      Any_request (Ssh_agentc_add_id_constrained
                     { privkey = p2; key_comment = c2; key_constraints = constraints2}) ->
      p1 = p2 && c1 = c2 && constraints1 = constraints2
      (* FIXME: unordered list in the constraints *)
    | Any_request (Ssh_agentc_add_smartcard_key_constrained
                     { smartcard_id = t1; smartcard_pin = pin1; smartcard_constraints = c1 }),
      Any_request (Ssh_agentc_add_smartcard_key_constrained
                     { smartcard_id = t2; smartcard_pin = pin2; smartcard_constraints = c2 }) ->
      t1 = t2 && pin1 = pin2 && c1 = c2
    | _, _ -> false
      (* FIXME: unordered list in the constraints *)
end

let m_request = (module Request : Alcotest.TESTABLE with type t = Ssh_agent.any_ssh_agent_request)

let () = Nocrypto_entropy_unix.initialize ()
let privkey = Nocrypto.Rsa.generate 1024
let pubkey = Nocrypto.Rsa.pub_of_priv privkey
let privkey = Ssh_agent.Privkey.Ssh_rsa privkey
let pubkey = Ssh_agent.Pubkey.Ssh_rsa pubkey

let serialize_parse s request =
  Alcotest.(check m_request) s (Ssh_agent.Any_request request)
    (let r = Ssh_agent.Serialize.(with_faraday (fun t ->
         write_ssh_agent_request t request)) in
     match Angstrom.parse_string Ssh_agent.Parse.ssh_agentc_message r with
     | Result.Ok req -> req
     | Result.Error e -> failwith e)

let serialize_parse_request_identities () =
  serialize_parse "serialize_parse_request_identities"
    Ssh_agent.Ssh_agentc_request_identities

let serialize_parse_sign_request () =
  serialize_parse "serialize_parse_sign_request"
    (Ssh_agent.Ssh_agentc_sign_request (pubkey, "KEY COMMENT", []))

let serialize_parse_add_identity () =
  serialize_parse "serialize_parse_add_identity"
    (Ssh_agent.Ssh_agentc_add_identity { privkey; key_comment = "KEY COMMENT" })

let serialize_parse_remove_identity () =
  serialize_parse "serialize_parse_remove_identity"
    (Ssh_agent.Ssh_agentc_remove_identity pubkey)

let serialize_parse_remove_all_identities () =
  serialize_parse "serialize_parse_remove_all_identities"
    Ssh_agent.Ssh_agentc_remove_all_identities

let serialize_parse_lock () =
  serialize_parse "serialize_parse_lock"
    (Ssh_agent.Ssh_agentc_lock "your favorite passphrase")

let serialize_parse_unlock () =
  serialize_parse "serialize_parse_unlock"
    (Ssh_agent.Ssh_agentc_unlock "your favorite passphrase")

let serialize_parse = [
  "request_identities", `Quick, serialize_parse_request_identities;
  "sign_request", `Quick, serialize_parse_sign_request;
  "add_identity", `Quick, serialize_parse_add_identity;
  "remove_identity", `Quick, serialize_parse_remove_identity;
  "remove_all_identities", `Quick, serialize_parse_remove_all_identities;
  "lock", `Quick, serialize_parse_lock;
  "unlock", `Quick, serialize_parse_unlock;
]


let () =
  Alcotest.run "Serialize |> Parse identity"
    [ "serialize_parse", serialize_parse ]
