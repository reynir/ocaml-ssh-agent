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
