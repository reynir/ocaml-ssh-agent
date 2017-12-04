open Ssh_agent
open Lwt.Infix

let pubkey_type_name pubkey =
  let open Ssh_agent.Pubkey in
  match pubkey with
  | Ssh_rsa _ -> "ssh-rsa"
  | Ssh_dss _ -> "ssh-dss"
  | Blob { key_type; _ } -> key_type

let with_faraday (f : Faraday.t -> unit) : string =
  let buf = Faraday.create 1024 in
  f buf;
  Faraday.serialize_to_string buf

let main () =
  let sock_path =
    match Sys.getenv_opt "SSH_AUTH_SOCK" with
    | Some path -> path
    | None -> failwith "$SSH_AUTH_SOCK not set" in
  let fd = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let () = Printf.printf "Connecting to %s...\n" sock_path in
  let () = Unix.connect fd Unix.(ADDR_UNIX sock_path) in
  let ic = Unix.in_channel_of_descr fd in
  let oc = Unix.out_channel_of_descr fd in
  let () = Printf.printf "Connected!\n" in
  let () =
    match Ssh_agent_unix.request (ic, oc) Ssh_agentc_request_identities with
    | Ok (Ssh_agent_identities_answer pubkeys) ->
      let () = Printf.printf "%d keys\n" (List.length pubkeys) in
      List.iter (fun Ssh_agent.Pubkey.{ comment; pubkey } ->
          Printf.printf "Key type %s with comment %s\n"
            (pubkey_type_name pubkey) comment)
        pubkeys
    | Ok (Ssh_agent_failure) ->
      failwith "Error: ssh-agent failure\n"
    | Error e ->
      failwith (Printf.sprintf "Error: %s\n" e) in
  let () = match Ssh_agent_unix.request (ic, oc)
                   Ssh_agentc_remove_all_identities with
  | Ok Ssh_agent_success ->
    print_endline "Success!"
  | Ok Ssh_agent_failure ->
    print_endline "Failure!"
  | Error e ->
    Printf.printf "Error: %s\n" e in
  let () = match Ssh_agent_unix.request (ic, oc) Ssh_agentc_request_identities with
    | Ok (Ssh_agent_identities_answer pubkeys) ->
      let () = Printf.printf "%d keys\n" (List.length pubkeys) in
      List.iter (fun Ssh_agent.Pubkey.{ comment; pubkey } ->
          Printf.printf "Key type %s with comment %s\n"
            (pubkey_type_name pubkey) comment)
        pubkeys
    | Ok Ssh_agent_failure ->
      Printf.eprintf "Error: Unexpected ssh-agent response\n"
    | Error e ->
      Printf.eprintf "Error: %s\n" e in
  ()

let () = main ()
