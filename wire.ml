open Angstrom

let byte =
  any_uint8

let boolean =
  any_char >>| ((<>) '\000')

let uint32 =
  BE.uint32

let uint64 =
  BE.uint64

(* XXX: int32 -> int coercion *)
let string =
  BE.uint32 >>= fun string_len ->
  take (Int32.to_int string_len)

(* XXX: int32 -> int coercion *)
let mpint =
  BE.uint32
  >>= fun mpint_len ->
  if mpint_len = 0l
  then return Z.zero
  else take (Int32.to_int mpint_len)
    >>= fun mpint ->
    return (Z.of_bits mpint)

let name_list =
  string >>|
  String.split_on_char ','

(*** Serializers ***)

let cstruct_of_byte byte =
  let r = Cstruct.create 1 in
  let () = Cstruct.set_uint8 r 0 byte in
  r

let cstruct_of_boolean b =
  cstruct_of_byte (if b then 1 else 0)

let cstruct_of_uint32 uint32 =
  let r = Cstruct.create 4 in
  let () = Cstruct.BE.set_uint32 r 0 uint32 in
  r

let cstruct_of_uint64 uint64 =
  let r = Cstruct.create 8 in
  let () = Cstruct.BE.set_uint64 r 0 uint64 in
  r

let cstruct_of_string s =
  let r = Cstruct.create (4 + String.length s) in
  let () = Cstruct.BE.set_uint32 r 0 (String.length s |> Int32.of_int) in
  let () = Cstruct.blit_from_string s 0 r 4 (String.length s) in
  r

let cstruct_of_mpint mpint =
  if mpint = Z.zero
  then Cstruct.create 4 (* Cstruct.create initializes with zeroes *)
  else
    let mpint = Nocrypto.Numeric.Z.to_cstruct_be mpint in
    let mpint_len = Cstruct.len mpint in
    let r = Cstruct.create (4 + Cstruct.len mpint) in
    let () = Cstruct.BE.set_uint32 r 0 (Int32.of_int mpint_len) in
    let () = Cstruct.blit mpint 0 r 4 (Cstruct.len mpint) in
    r

let cstruct_of_name_list name_list =
  cstruct_of_string @@ String.concat "," name_list
