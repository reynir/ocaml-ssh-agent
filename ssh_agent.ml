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
  type ssh_dss = {
    p : Z.t;
    q : Z.t;
    g : Z.t;
    y : Z.t;
  }

  type ssh_rsa = {
    e : Z.t;
    n : Z.t;
  }

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
    Wire.mpint >>= fun g ->
    Wire.mpint >>= fun y ->
    return (Ssh_dss { p; q; g; y })

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

end

type ssh_agent_request =
  | Ssh_agentc_request_identities
  | Ssh_agentc_sign_request of Pubkey.t * string * Protocol_number.sign_flag list

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
