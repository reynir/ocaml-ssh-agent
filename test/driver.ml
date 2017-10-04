open Ssh_agent

let () =
  let sock_path =
    match Sys.getenv_opt "SSH_AUTH_SOCK" with
    | Some path -> path
    | None -> failwith "$SSH_AUTH_SOCK not set" in
  let fd = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let () = Printf.printf "Connecting to %s...\n" sock_path in
  let () = Unix.connect fd Unix.(ADDR_UNIX sock_path) in
  let () = Printf.printf "Connected!\n" in
  let buf = Cstruct.create 4 in
  let () = Cstruct.BE.set_uint32 buf 0 1l in
  let _ = Unix.write fd (Cstruct.to_string buf) 0 4 in
  let _ = Ssh_agent.write_ssh_agent fd SSH_AGENTC_REQUEST_IDENTITIES in
  let inc = Unix.in_channel_of_descr fd in
  match Angstrom_unix.parse
          Ssh_agent.ssh_agent_message
          inc with
  | unconsumed, Ok (Ssh_agent_identities_answer pubkeys) ->
    Printf.printf "%d keys\n" (List.length pubkeys);
    List.iter (fun Ssh_agent.Pubkey.{ comment; pubkey } ->
        Printf.printf "Key type %s with comment %s\n" 
          (Ssh_agent.Pubkey.type_name pubkey) comment)
      pubkeys
  | unconsumed, Ok _ ->
    Printf.eprintf "Error: Unexpected ssh-agent response\n"
  | unconsumed, Error e ->
    Printf.eprintf "Error: %s\n" e
