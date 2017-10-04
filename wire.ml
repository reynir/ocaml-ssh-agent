open Angstrom

let byte =
  any_char

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

let string_constant s =
  let s_len = String.length s in
  BE.int32 >>= fun len ->
  if len <> Int32.of_int s_len
  then fail "Wrong string length"
  else take s_len >>= fun s' ->
    if s <> s'
    then fail "Wrong string"
    else return s'

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
