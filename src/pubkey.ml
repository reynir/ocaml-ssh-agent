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
