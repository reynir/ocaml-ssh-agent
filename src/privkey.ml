type ssh_dss = Nocrypto.Dsa.priv

type ssh_rsa = Nocrypto.Rsa.priv

type t =
  | Ssh_dss of ssh_dss
  | Ssh_rsa of ssh_rsa
  | Blob of {
      key_type : string;
      key_blob : string;
    }

let ssh_dss =
  let open Angstrom in
  Wire.mpint >>= fun p ->
  Wire.mpint >>= fun q ->
  Wire.mpint >>= fun gg ->
  Wire.mpint >>= fun y ->
  Wire.mpint >>= fun x ->
  return (Ssh_dss { p; q; gg; y; x })

let ssh_rsa =
  let open Angstrom in
  Wire.mpint >>= fun n ->
  Wire.mpint >>= fun e ->
  Wire.mpint >>= fun d ->
  Wire.mpint >>= fun iqmp ->
  Wire.mpint >>= fun p ->
  Wire.mpint >>= fun q ->
  (* FIXME: How do the parameters correspond to Nocrypto.Rsa.priv ? *)
  return (Ssh_rsa (Nocrypto.Rsa.priv_of_primes ~e ~p ~q))

let blob key_type =
  let open Angstrom in
  take_while (fun _ -> true) >>= fun key_blob ->
  return (Blob { key_type; key_blob })

let privkey =
  let open Angstrom in
  Wire.string >>= function
  | "ssh-dss" ->
    ssh_dss
  | "ssh-rsa" ->
    ssh_rsa
  | key_type ->
    blob key_type

let comment = Wire.string

let write_privkey t privkey =
  match privkey with
  | Ssh_dss { p; q; gg; x; y } ->
    Wire.write_string t "ssh-dss";
    Wire.write_mpint t p;
    Wire.write_mpint t q;
    Wire.write_mpint t gg;
    Wire.write_mpint t y;
    Wire.write_mpint t x
  | Ssh_rsa { e; d; n; p; q; dp; dq; q' } ->
    (* iqmp (inverse of q modulo p) is q' *)
    Wire.write_string t "ssh-rsa";
    Wire.write_mpint t n;
    Wire.write_mpint t e;
    Wire.write_mpint t d;
    Wire.write_mpint t q';
    Wire.write_mpint t p;
    Wire.write_mpint t q
  | Blob { key_type; key_blob } ->
    Wire.write_string t key_type;
    Faraday.write_string t key_blob
