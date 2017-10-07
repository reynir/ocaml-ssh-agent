open Ssh_agent

let main () =
  let sock_path =
    match Sys.getenv_opt "SSH_AUTH_SOCK" with
    | Some path -> path
    | None -> failwith "$SSH_AUTH_SOCK not set" in
  let fd = Lwt_unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let () = Printf.printf "Connecting to %s...\n" sock_path in
  let%lwt () = Lwt_unix.connect fd Unix.(ADDR_UNIX sock_path) in
  let () = Printf.printf "Connected!\n" in
  let%lwt () = Lwt_cstruct.complete (Lwt_cstruct.write fd) @@
    cstruct_of_ssh_agent_request Ssh_agentc_request_identities in
  let inc = Lwt_io.of_fd Lwt_io.input fd in
  match%lwt Angstrom_lwt_unix.parse
          Ssh_agent.ssh_agent_message
          inc with
  | unconsumed, Ok (Ssh_agent_identities_answer pubkeys) ->
    Printf.printf "%d keys\n" (List.length pubkeys);
    Lwt.return @@
    List.iter (fun Ssh_agent.Pubkey.{ comment; pubkey } ->
        Printf.printf "Key type %s with comment %s\n" 
          (Ssh_agent.Pubkey.type_name pubkey) comment)
      pubkeys
  | unconsumed, Ok _ ->
    Lwt_io.eprintf "Error: Unexpected ssh-agent response\n"
  | unconsumed, Error e ->
    Lwt_io.eprintf "Error: %s\n" e

let () = Lwt_main.run @@ main ()
