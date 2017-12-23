include Types

module Parse = Parse
module Serialize = Serialize

let is_extension_request (type a) (req : a ssh_agent_request) =
  match req with
  | Ssh_agentc_extension _ -> true
  | _ -> false

let sign priv (sign_flags : Protocol_number.sign_flag list) blob =
  match priv with
  | Privkey.Ssh_dss key ->
    failwith "Not implemented :-("
  | Privkey.Ssh_rsa key ->
    let alg_string, to_sign =
      if List.mem Protocol_number.SSH_AGENT_RSA_SHA2_512 sign_flags
      then let digest = Nocrypto.Hash.SHA512.digest (Cstruct.of_string blob) in
        "rsa-sha2-512", Cstruct.append Util.id_sha512 digest
      else if List.mem Protocol_number.SSH_AGENT_RSA_SHA2_256 sign_flags
      then let digest = Nocrypto.Hash.SHA256.digest (Cstruct.of_string blob) in
        "rsa-sha2-256", Cstruct.append Util.id_sha256 digest
      else let digest = Nocrypto.Hash.SHA1.digest (Cstruct.of_string blob) in
        "ssh-rsa", Cstruct.append Util.id_sha1 digest in
    let signed = Nocrypto.Rsa.PKCS1.sig_encode ~key to_sign in
    Serialize.(with_faraday (fun t ->
        Wire.write_string t alg_string;
        Wire.write_string t (Cstruct.to_string signed)))
