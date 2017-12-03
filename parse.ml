open Types
(* Angstrom helpers *)
let take32 n =
  Angstrom.take (Int32.to_int n)

let count32 n =
  Angstrom.count (Int32.to_int n)

let parse_lift p1 p2 =
  let open Angstrom in
  p1 >>= fun s ->
  match parse_string p2 s with
  | Ok a -> Angstrom.return a
  | Error e -> Angstrom.fail e

let id_entry =
  let open Angstrom in
  parse_lift Wire.string Pubkey.pubkey >>= fun pubkey ->
  Wire.string >>= fun comment ->
  return { Pubkey.pubkey; comment }

let ssh_agent_identities_answer =
  let open Angstrom in
  BE.int32 >>= fun nkeys ->
  count32 nkeys id_entry

let ssh_agent_sign_response =
  let open Angstrom in
  Wire.string >>= fun signature ->
  return (Ssh_agent_sign_response signature)

let ssh_agent_message_type =
  let open Angstrom in
  Angstrom.any_uint8 >>|
  Protocol_number.int_to_ssh_agent >>=
  let open Protocol_number in function
  | Some SSH_AGENT_FAILURE ->
    return (Any_response Ssh_agent_failure)
  | Some SSH_AGENT_SUCCES ->
    return (Any_response Ssh_agent_success)
  | Some SSH_AGENT_IDENTITIES_ANSWER ->
    ssh_agent_identities_answer >>| fun identities ->
    Any_response (Ssh_agent_identities_answer identities)
  | Some SSH_AGENT_SIGN_RESPONSE ->
    ssh_agent_sign_response >>| fun r ->
    Any_response r
  | Some protocol_number ->
    fail ("Unimplemeted protocol number: " ^
          ssh_agent_to_string protocol_number)
  | None ->
    fail "Unknown ssh-agent protocol number"


let ssh_agent_message =
  let open Angstrom in
  BE.int32 >>= fun msg_len ->
  parse_lift (take32 msg_len)
    ssh_agent_message_type

let ssh_agentc_sign_request =
  let open Angstrom in
  parse_lift Wire.string Pubkey.pubkey >>= fun pubkey ->
  Wire.string >>= fun data ->
  Wire.uint32 >>= fun mask ->
  let flags = Protocol_number.mask_to_sign_flags (Int32.to_int mask) in
  return (Ssh_agentc_sign_request (pubkey, data, flags))

let ssh_agentc_add_identity =
  let open Angstrom in
  Privkey.privkey >>= fun privkey ->
  Wire.string >>= fun key_comment ->
  return (Ssh_agentc_add_identity { privkey; key_comment })

let ssh_agentc_remove_identity =
  let open Angstrom in
  Pubkey.pubkey >>= fun pubkey ->
  return (Ssh_agentc_remove_identity pubkey)

let ssh_agentc_add_smartcard_key =
  let open Angstrom in
  Wire.string >>= fun smartcard_id ->
  Wire.string >>= fun smartcard_pin ->
  return (Ssh_agentc_add_smartcard_key { smartcard_id; smartcard_pin })

let ssh_agentc_remove_smartcard_key =
  let open Angstrom in
  Wire.string >>= fun smartcard_reader_id ->
  Wire.string >>= fun smartcard_reader_pin ->
  return (Ssh_agentc_remove_smartcard_key { smartcard_reader_id; smartcard_reader_pin })

let ssh_agentc_lock =
  let open Angstrom in
  Wire.string >>= fun passphrase ->
  return (Ssh_agentc_lock passphrase)

let ssh_agentc_unlock =
  let open Angstrom in
  Wire.string >>= fun passphrase ->
  return (Ssh_agentc_unlock passphrase)

let ssh_agentc_extension =
  let open Angstrom in
  Wire.string >>= fun extension_type ->
  take_while (fun _ -> true) >>= fun extension_contents ->
  return (Ssh_agentc_extension { extension_type; extension_contents })


let ssh_agentc_message_type =
  let open Angstrom in
  let req p = p >>| fun r -> Any_request r in
  any_uint8 >>|
  Protocol_number.int_to_ssh_agent >>=
  let open Protocol_number in function
    | Some SSH_AGENTC_REQUEST_IDENTITIES ->
      return (Any_request Ssh_agentc_request_identities)
    | Some SSH_AGENTC_SIGN_REQUEST ->
      req ssh_agentc_sign_request
    | Some SSH_AGENTC_ADD_IDENTITY ->
      fail "Not implemented"
    | Some SSH_AGENTC_REMOVE_IDENTITY ->
      req ssh_agentc_remove_identity
    | Some SSH_AGENTC_REMOVE_ALL_IDENTITIES ->
      return (Any_request Ssh_agentc_remove_all_identities)
    | Some SSH_AGENTC_ADD_SMARTCARD_KEY ->
      req ssh_agentc_add_smartcard_key
    | Some SSH_AGENTC_REMOVE_SMARTCARD_KEY ->
      req ssh_agentc_remove_smartcard_key
    | Some SSH_AGENTC_LOCK ->
      req ssh_agentc_lock
    | Some SSH_AGENTC_UNLOCK ->
      req ssh_agentc_unlock
    | Some SSH_AGENTC_ADD_ID_CONSTRAINED ->
      fail "Not implemented"
    | Some SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED ->
      fail "Not implemented"
    | Some SSH_AGENTC_EXTENSION ->
      req ssh_agentc_extension
    | None | Some _ ->
      fail "Not an ssh-agent request"

let ssh_agentc_message =
  let open Angstrom in
  BE.int32 >>= fun msg_len ->
  parse_lift (take32 msg_len)
    ssh_agentc_message_type
