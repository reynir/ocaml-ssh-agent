open Angstrom

let byte =
  any_uint8

let boolean =
  any_char >>| ((<>) '\000')

let uint32 =
  BE.int32

let uint64 =
  BE.int64

(* XXX: int32 -> int coercion *)
let string =
  BE.int32 >>= fun string_len ->
  take (Int32.to_int string_len)

(* XXX: int32 -> int coercion *)
(* FIXME: negative numbers *)
let mpint =
  BE.int32
  >>= fun mpint_len ->
  if mpint_len = 0l
  then return Z.zero
  else take (Int32.to_int mpint_len)
    >>= fun mpint ->
    return (Nocrypto.Numeric.Z.of_cstruct_be (Cstruct.of_string mpint))

let name_list =
  string >>|
  String.split_on_char ','

(*** Serializers ***)

let write_byte t byte =
  Faraday.write_uint8 t byte

let write_boolean t b =
  Faraday.write_uint8 t (if b then 1 else 0)

let write_uint32 t uint32 =
  Faraday.BE.write_uint32 t uint32

let write_uint64 t uint64 =
  Faraday.BE.write_uint64 t uint64

let write_string t s =
  Faraday.BE.write_uint32 t (String.length s |> Int32.of_int);
  Faraday.write_string t s

let write_mpint t mpint =
  if mpint = Z.zero
  then write_uint32 t 0l
  else
    let mpint = Nocrypto.Numeric.Z.to_cstruct_be mpint in
    let mpint_padded =
      if Cstruct.get_uint8 mpint 0 land 0x80 <> 0
      then Cstruct.append (Cstruct.of_string "\000") mpint
      else mpint in
    write_string t (Cstruct.to_string mpint_padded)

let write_name_list t name_list =
  write_string t (String.concat "," name_list)

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

(* FIXME: Negative numbers *)
let cstruct_of_mpint mpint =
  if mpint = Z.zero
  then cstruct_of_uint32 Int32.zero
  else
    let mpint = Nocrypto.Numeric.Z.to_cstruct_be mpint in
    let mpint_padded =
      if Cstruct.get_uint8 mpint 0 land 0x80 <> 0
      then Cstruct.append (Cstruct.of_string "\000") mpint
      else mpint in
    Cstruct.append
      (cstruct_of_uint32 (Int32.of_int (Cstruct.len mpint_padded)))
      mpint_padded

let cstruct_of_name_list name_list =
  cstruct_of_string @@ String.concat "," name_list
