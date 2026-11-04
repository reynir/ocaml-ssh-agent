module Pubkey = struct
  type ssh_dss = Mirage_crypto_pk.Dsa.pub

  type ssh_rsa = Mirage_crypto_pk.Rsa.pub

  type ssh_ed25519 = Mirage_crypto_ec.Ed25519.pub

  type options = (string * string) list

  type ssh_rsa_cert_tbs = {
    nonce : string;
    pubkey : ssh_rsa;
    serial : int64;
    typ : Protocol_number.ssh_cert_type;
    key_id : string;
    valid_principals : string list;
    valid_after : int64;
    valid_before : int64;
    critical_options : options;
    extensions : options;
    reserved : string;
    signature_key : t;
  }
  and ssh_rsa_cert = {
    to_be_signed : ssh_rsa_cert_tbs;
    signature : string;
  }
  and t =
    | Ssh_dss of ssh_dss
    | Ssh_rsa of ssh_rsa
    | Ssh_rsa_cert of ssh_rsa_cert
    | Ssh_ed25519 of ssh_ed25519
    | Blob of {
        key_type : string;
        key_blob : string;
      }

  let options_equal =
    let eq (a1, a2) (b1, b2) = String.equal a1 b1 && String.equal a2 b2 in
    List.equal eq

  let dsa_equal
      { Mirage_crypto_pk.Dsa.p=p1; q=q1; gg=gg1; y=y1 }
      { Mirage_crypto_pk.Dsa.p=p2; q=q2; gg=gg2; y=y2 }
    =
    Z.equal p1 p2
    && Z.equal q1 q2
    && Z.equal gg1 gg2
    && Z.equal y1 y2

  let rsa_equal
      ({ e; n } : Mirage_crypto_pk.Rsa.pub)
      (b : Mirage_crypto_pk.Rsa.pub) =
      Z.equal e b.e && Z.equal n b.n

  let rec ssh_rsa_cert_tbs_equal
      { nonce; pubkey; serial; typ; key_id; valid_principals;
        valid_after; valid_before; critical_options;
        extensions; reserved; signature_key; }
      b =
    String.equal nonce b.nonce
    && rsa_equal pubkey b.pubkey
    && Int64.equal serial b.serial
    && typ = b.typ
    && String.equal key_id b.key_id
    && List.equal String.equal valid_principals b.valid_principals
    && Int64.equal valid_after b.valid_after
    && Int64.equal valid_before b.valid_before
    && options_equal critical_options b.critical_options
    && options_equal extensions b.extensions
    && String.equal reserved b.reserved
    && equal signature_key b.signature_key
  and ssh_rsa_cert_equal { to_be_signed; signature } b =
    String.equal signature b.signature
    && ssh_rsa_cert_tbs_equal to_be_signed b.to_be_signed
  and equal k1 k2 =
    match k1, k2 with
    | Ssh_ed25519 k1, Ssh_ed25519 k2 ->
      Mirage_crypto_ec.Ed25519.(String.equal (pub_to_octets k1) (pub_to_octets k2))
    | Ssh_dss a, Ssh_dss b ->
      dsa_equal a b
    | Ssh_rsa a, Ssh_rsa b -> rsa_equal a b
    | Ssh_rsa_cert a, Ssh_rsa_cert b ->
      ssh_rsa_cert_equal a b
    | Blob { key_type; key_blob }, Blob b ->
      String.equal key_type b.key_type && String.equal key_blob b.key_blob
    | _, _ -> false
end

module Privkey = struct
  type ssh_dss = Mirage_crypto_pk.Dsa.priv

  type ssh_rsa = Mirage_crypto_pk.Rsa.priv

  type ssh_ed25519 = Mirage_crypto_ec.Ed25519.priv

  type t =
    | Ssh_dss of ssh_dss
    | Ssh_rsa of ssh_rsa
    | Ssh_rsa_cert of ssh_rsa * Pubkey.ssh_rsa_cert
    | Ssh_ed25519 of ssh_ed25519
    | Blob of {
        key_type : string;
        key_blob : string;
      }
end

type identity = {
  pubkey : Pubkey.t;
  comment : string;
}

type sign_flag = Protocol_number.sign_flag =
  | SSH_AGENT_RSA_SHA2_256
  | SSH_AGENT_RSA_SHA2_512

type key_constraint =
  | Lifetime of int32 (* uint32 *)
  | Confirm

type ssh_agent_request_type = [
  | `Ssh_agentc_request_identities
  | `Ssh_agentc_sign_request
  | `Ssh_agentc_extension
  | `Ssh_agentc_successable
]

type _ ssh_agent_request =
  | Ssh_agentc_request_identities :
      [`Ssh_agentc_request_identities] ssh_agent_request
  | Ssh_agentc_sign_request :
      Pubkey.t * string * Protocol_number.sign_flag list
    -> [`Ssh_agentc_sign_request] ssh_agent_request
  | Ssh_agentc_add_identity :
      { privkey : Privkey.t; key_comment : string }
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_remove_identity :
      Pubkey.t
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_remove_all_identities :
      [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_add_smartcard_key :
      { smartcard_id : string; smartcard_pin : string }
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_remove_smartcard_key :
      { smartcard_reader_id : string; smartcard_reader_pin : string }
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_lock :
      string
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_unlock :
      string
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_add_id_constrained :
      { privkey : Privkey.t; key_comment : string; key_constraints : key_constraint list }
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_add_smartcard_key_constrained :
      { smartcard_id : string; smartcard_pin : string;
        smartcard_constraints : key_constraint list }
    -> [`Ssh_agentc_successable] ssh_agent_request
  | Ssh_agentc_extension :
      { extension_type : string; extension_contents : string }
    -> [`Ssh_agentc_extension] ssh_agent_request

type any_ssh_agent_request =
  Any_request : 'a ssh_agent_request -> any_ssh_agent_request

type _ ssh_agent_response =
  | Ssh_agent_failure : [<ssh_agent_request_type] ssh_agent_response
  | Ssh_agent_success : [`Ssh_agentc_successable] ssh_agent_response
  | Ssh_agent_extension_failure : [`Ssh_agentc_extension] ssh_agent_response
  | Ssh_agent_extension_blob : string
    -> [`Ssh_agentc_extension] ssh_agent_response
  (** Generic uninterpreted response - it's up to the library user to interpret
   *  the message body. *)
  | Ssh_agent_identities_answer : identity list
    -> [`Ssh_agentc_request_identities] ssh_agent_response
  | Ssh_agent_sign_response : string
    -> [`Ssh_agentc_sign_request] ssh_agent_response

type any_ssh_agent_response =
  Any_response : 'a ssh_agent_response -> any_ssh_agent_response

type request_handler =
  { handle : 'a . 'a ssh_agent_request -> 'a ssh_agent_response; }
