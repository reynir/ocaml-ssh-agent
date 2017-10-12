module Z = Nocrypto.Numeric.Z

(* Angstrom helpers *)
let take32 n =
  Angstrom.take (Int32.to_int n)

let count32 n =
  Angstrom.count (Int32.to_int n)

let parse_lift s p =
  let open Angstrom in
  s >>= fun s ->
  match parse_only p (`String s) with
  | Ok a -> Angstrom.return a
  | Error e -> Angstrom.fail e

module Pubkey = struct
  type ssh_dss = Nocrypto.Dsa.pub

  type ssh_rsa = Nocrypto.Rsa.pub

  type t =
    | Ssh_dss of ssh_dss
    | Ssh_rsa of ssh_rsa
    | Blob of { 
        key_type : string;
        key_blob : string;
      }

  let type_name = function
    | Ssh_dss _ -> "ssh-dss"
    | Ssh_rsa _ -> "ssh-rsa"
    | Blob { key_type; _ } -> key_type

  let ssh_dss =
    let open Angstrom in
    Wire.mpint >>= fun p ->
    Wire.mpint >>= fun q ->
    Wire.mpint >>= fun gg ->
    Wire.mpint >>= fun y ->
    return (Ssh_dss { p; q; gg; y })

  let ssh_rsa =
    let open Angstrom in
    Wire.mpint >>= fun e ->
    Wire.mpint >>= fun n ->
    return (Ssh_rsa { e; n })

  let blob key_type =
    Angstrom.(take_while (fun _ -> true) >>= fun key_blob ->
              return @@ Blob { key_type; key_blob; })

  let pubkey =
    let open Angstrom in
    Wire.string >>= function
    | "ssh-dss" ->
      ssh_dss
    | "ssh-rsa" ->
      ssh_rsa
    | key_type ->
      blob key_type

  let comment = Wire.string

  type identity = {
    pubkey : t;
    comment : string;
  }

  let to_cstruct pubkey =
    let ( <+> ) = Cstruct.append in
    match pubkey with
    | Ssh_dss { p; q; gg; y } ->
      Wire.cstruct_of_string "ssh-dss" <+>
      Wire.cstruct_of_mpint p <+>
      Wire.cstruct_of_mpint q <+>
      Wire.cstruct_of_mpint gg <+>
      Wire.cstruct_of_mpint y
    | Ssh_rsa { e; n } ->
      Wire.cstruct_of_string "ssh-rsa" <+>
      Wire.cstruct_of_mpint e <+>
      Wire.cstruct_of_mpint n
    | Blob { key_type; key_blob } ->
      Wire.cstruct_of_string key_type <+>
      Cstruct.of_string key_blob

end

(** XXX: Empty type - only as a placeholder *)
type void = { elim_empty : 'a. 'a }

type ssh_agent_request =
  | Ssh_agentc_request_identities
  | Ssh_agentc_sign_request of Pubkey.t * string * Protocol_number.sign_flag list
  | Ssh_agentc_add_identity of { key_type : string; key_contents : string; key_comment : string }
  | Ssh_agentc_remove_identity of Pubkey.t
  | Ssh_agentc_remove_all_identities
  | Ssh_agentc_add_smartcard_key of void
  | Ssh_agentc_remove_smartcard_key of void
  | Ssh_agentc_lock of string
  | Ssh_agentc_unlock of string
  | Ssh_agentc_add_id_constrained of void
  | Ssh_agentc_add_smartcard_key_constrained of void
  | Ssh_agentc_extension of string * string (** extension type * extension contents *)

type ssh_agent_response =
  | Ssh_agent_failure
  | Ssh_agent_success
  (* ... *)
  | Ssh_agent_identities_answer of Pubkey.identity list
  | Ssh_agent_not_implemented of Protocol_number.ssh_agent

let id_entry =
  let open Angstrom in
  parse_lift Wire.string Pubkey.pubkey >>= fun pubkey ->
  Wire.string >>= fun comment ->
  return { Pubkey.pubkey; comment }

let ssh_agent_identities_answer =
  let open Angstrom in
  BE.int32 >>= fun nkeys ->
  count32 nkeys id_entry

let ssh_agent_message_type =
  let open Angstrom in
  Angstrom.any_uint8 >>|
  Protocol_number.int_to_ssh_agent >>=
  let open Protocol_number in function
  | Some SSH_AGENT_FAILURE ->
    return Ssh_agent_failure
  | Some SSH_AGENT_SUCCES ->
    return Ssh_agent_success
  | Some SSH_AGENT_IDENTITIES_ANSWER ->
    ssh_agent_identities_answer >>| fun identities ->
    Ssh_agent_identities_answer identities
  | Some protocol_number ->
    fail ("Unimplemeted protocol number: " ^
          ssh_agent_to_string protocol_number)
  | None ->
    fail "Unknown ssh-agent protocol number"


let ssh_agent_message =
  let open Angstrom in
  BE.uint32 >>= fun msg_len ->
  parse_lift (take32 msg_len)
    ssh_agent_message_type

let write_ssh_agent fd n =
  let n = Protocol_number.ssh_agent_to_int n in
  Unix.write fd (String.make 1 (char_of_int n)) 0 1

let cstruct_of_ssh_agent_request req =
  let message =
    match req with
    | Ssh_agentc_request_identities ->
      Protocol_number.(cstruct_of_ssh_agent SSH_AGENTC_REQUEST_IDENTITIES)
    | Ssh_agentc_remove_all_identities ->
      Protocol_number.(cstruct_of_ssh_agent SSH_AGENTC_REMOVE_ALL_IDENTITIES)
    | Ssh_agentc_remove_identity pubkey ->
      Cstruct.append
        Protocol_number.(cstruct_of_ssh_agent SSH_AGENTC_REMOVE_IDENTITY)
        (Pubkey.to_cstruct pubkey)
    | Ssh_agentc_lock passphrase ->
      let r = Cstruct.create (1 + String.length passphrase) in
      Cstruct.set_uint8 r 0 Protocol_number.(ssh_agent_to_int SSH_AGENTC_LOCK);
      Cstruct.blit_from_string passphrase 0 r 1 (String.length passphrase);
      r
    | Ssh_agentc_unlock passphrase ->
      let r = Cstruct.create (1 + String.length passphrase) in
      Cstruct.set_uint8 r 0 Protocol_number.(ssh_agent_to_int SSH_AGENTC_UNLOCK);
      Cstruct.blit_from_string passphrase 0 r 1 (String.length passphrase);
      r
    | _ ->
      failwith "Not implemented"
  in
  let r = Cstruct.create (4 + Cstruct.len message) in
  Cstruct.BE.set_uint32 r 0 (Int32.of_int (Cstruct.len message));
  Cstruct.blit message 0 r 4 (Cstruct.len message);
  r

module Wire = Wire
module Protocol_number = Protocol_number
