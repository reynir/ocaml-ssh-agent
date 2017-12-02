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

let with_faraday (f : Faraday.t -> unit) : string =
  let buf = Faraday.create 1024 in
  f buf;
  Faraday.serialize_to_string buf

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

  let write_pubkey t pubkey =
    match pubkey with
    | Ssh_dss { p; q; gg; y } ->
      Wire.write_string t "ssh-dss";
      Wire.write_mpint t p;
      Wire.write_mpint t q;
      Wire.write_mpint t gg;
      Wire.write_mpint t y
    | Ssh_rsa { e; n } ->
      Wire.write_string t "ssh-rsa";
      Wire.write_mpint t e;
      Wire.write_mpint t n
    | Blob { key_type; key_blob } ->
      Wire.write_string t key_type;
      Faraday.write_string t key_blob

end

type ssh_agent_request_type = [
  | `Ssh_agentc_request_identities
  | `Ssh_agentc_sign_request
  | `Ssh_agentc_add_identity
  | `Ssh_agentc_remove_identity
  | `Ssh_agentc_remove_all_identities
  | `Ssh_agentc_add_smartcard_key
  | `Ssh_agentc_remove_smartcard_key
  | `Ssh_agentc_lock
  | `Ssh_agentc_unlock
  | `Ssh_agentc_add_id_constrained
  | `Ssh_agentc_add_smartcard_key_constrained
  | `Ssh_agentc_extension
]

type _ ssh_agent_request =
  | Ssh_agentc_request_identities :
      [`Ssh_agentc_request_identities] ssh_agent_request
  | Ssh_agentc_sign_request :
      Pubkey.t * string * Protocol_number.sign_flag list
    -> [`Ssh_agentc_sign_request] ssh_agent_request
  | Ssh_agentc_add_identity :
      { key_type : string; key_contents : string; key_comment : string }
    -> [`Ssh_agentc_add_identity] ssh_agent_request
  | Ssh_agentc_remove_identity :
      Pubkey.t
    -> [`Ssh_agentc_remove_identity] ssh_agent_request
  | Ssh_agentc_remove_all_identities :
      [`Ssh_agentc_remove_all_identities] ssh_agent_request
  | Ssh_agentc_add_smartcard_key :
      { smartcard_id : string; smartcard_pin : string }
    -> [`Ssh_agentc_add_smartcard_key] ssh_agent_request
  | Ssh_agentc_remove_smartcard_key :
      { smartcard_reader_id : string; smartcard_reader_pin : string }
    -> [`Ssh_agentc_remove_smartcard_key] ssh_agent_request
  | Ssh_agentc_lock :
      string
    -> [`Ssh_agentc_lock] ssh_agent_request
  | Ssh_agentc_unlock :
      string
    -> [`Ssh_agentc_unlock] ssh_agent_request
  | Ssh_agentc_add_id_constrained :
      { key_type : string; key_contents : string;
        key_comment : string; key_constraints : Protocol_number.key_constraint list }
    -> [`Ssh_agentc_add_id_constrained] ssh_agent_request
  | Ssh_agentc_add_smartcard_key_constrained :
      { smartcard_id : string; smartcard_pin : string;
        smartcard_constraints : Protocol_number.key_constraint list }
    -> [`Ssh_agentc_add_smartcard_key_constrained] ssh_agent_request
  | Ssh_agentc_extension :
      { extension_type : string; extension_contents : string }
    -> [`Ssh_agentc_extension] ssh_agent_request
  (** extension type * extension contents *)

type any_ssh_agent_request =
  Any_request : 'a ssh_agent_request -> any_ssh_agent_request

type _ ssh_agent_response =
  | Ssh_agent_failure : ssh_agent_request_type ssh_agent_response
  | Ssh_agent_success : ssh_agent_request_type ssh_agent_response
        (* TODO: refine when success can happen *)
  | Ssh_agent_extension_failure : [`Ssh_agentc_extension] ssh_agent_response
  | Ssh_agent_identities_answer : Pubkey.identity list
    -> [`Ssh_agentc_request_identities] ssh_agent_response
  | Ssh_agent_sign_response : string
    -> [`Ssh_agentc_sign_request] ssh_agent_response

type any_ssh_agent_response =
  Any_response : 'a ssh_agent_response -> any_ssh_agent_response

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

let ssh_agentc_message =
  let open Angstrom in
  BE.int32 >>= fun msg_len ->
  parse_lift (take32 msg_len)
    ssh_agentc_message_type

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
      | Ssh_agentc_add_identity { key_type; key_contents; key_comment } ->
        Protocol_number.(write_ssh_agent t SSH_AGENTC_ADD_IDENTITY);
        Wire.write_string t key_type;
        Faraday.write_string t key_contents;
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

module Wire = Wire
module Protocol_number = Protocol_number
