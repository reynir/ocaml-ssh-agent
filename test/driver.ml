open Ssh_agent
open Lwt.Infix

let with_faraday (f : Faraday.t -> unit) : string =
  let buf = Faraday.create 1024 in
  f buf;
  Faraday.serialize_to_string buf

let main () =
  let sock_path =
    match Sys.getenv_opt "SSH_AUTH_SOCK" with
    | Some path -> path
    | None -> failwith "$SSH_AUTH_SOCK not set" in
  let fd = Lwt_unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let%lwt () = Lwt_io.printf "Connecting to %s...\n" sock_path in
  let%lwt () = Lwt_unix.connect fd Unix.(ADDR_UNIX sock_path) in
  let inc = Lwt_io.of_fd Lwt_io.input fd in
  let outc = Lwt_io.of_fd Lwt_io.output fd in
  let%lwt () = Lwt_io.printf "Connected!\n" in
  (*let%lwt () = Lwt_cstruct.complete (Lwt_cstruct.write fd) @@
    cstruct_of_ssh_agent_request Ssh_agentc_request_identities in *)
  let%lwt () = Lwt_io.write outc
      (with_faraday (fun buf ->
           Serialize.write_ssh_agent_request buf Ssh_agentc_request_identities)) in
  let%lwt pubkeys =
    match%lwt Angstrom_lwt_unix.parse
                Ssh_agent.Parse.ssh_agent_message
                inc with
    | unconsumed, Ok (Any_response (Ssh_agent_identities_answer pubkeys)) ->
      let%lwt () = Lwt_io.printf "%d keys\n" (List.length pubkeys) in
      let%lwt () = Lwt_list.iter_s (fun Ssh_agent.Pubkey.{ comment; pubkey } ->
          Lwt_io.printf "Key type %s with comment %s\n"
            (Ssh_agent.Pubkey.type_name pubkey) comment)
          pubkeys in
      Lwt.return pubkeys
    | unconsumed, Ok _ ->
      Lwt.fail_with "Error: Unexpected ssh-agent response\n"
    | unconsumed, Error e ->
      Lwt.fail_with (Printf.sprintf "Error: %s\n" e) in
  let%lwt () = Lwt_io.write outc
      (with_faraday (fun buf ->
           Serialize.write_ssh_agent_request buf Ssh_agentc_remove_all_identities)) in
  let%lwt () =
    match%lwt Angstrom_lwt_unix.parse
                Ssh_agent.Parse.ssh_agent_message
                inc with
    | unconsumed, Ok (Any_response Ssh_agent_success) ->
      Lwt_io.printl "Success!"
    | unconsumed, Ok (Any_response Ssh_agent_failure) ->
      Lwt_io.printl "Failure!"
    | unconsumed, Ok _ ->
      Lwt_io.eprintf "Error: Unexpected ssh-agent response\n"
    | unconsumed, Error e ->
      Lwt_io.eprintf "Error: %s\n" e in
  (*let%lwt () = Lwt_cstruct.complete (Lwt_cstruct.write fd) @@
    cstruct_of_ssh_agent_request Ssh_agentc_request_identities in*)
  let%lwt () = Lwt_io.write outc
      (with_faraday (fun buf ->
           Serialize.write_ssh_agent_request buf Ssh_agentc_request_identities)) in
  let%lwt () =
    match%lwt Angstrom_lwt_unix.parse
                Ssh_agent.Parse.ssh_agent_message
                inc with
    | unconsumed, Ok (Any_response (Ssh_agent_identities_answer pubkeys)) ->
      let%lwt () = Lwt_io.printf "%d keys\n" (List.length pubkeys) in
      Lwt_list.iter_s (fun Ssh_agent.Pubkey.{ comment; pubkey } ->
          Lwt_io.printf "Key type %s with comment %s\n"
            (Ssh_agent.Pubkey.type_name pubkey) comment)
        pubkeys
    | unconsumed, Ok _ ->
      Lwt_io.eprintf "Error: Unexpected ssh-agent response\n"
    | unconsumed, Error e ->
      Lwt_io.eprintf "Error: %s\n" e in
  Lwt.return_unit

let () = Lwt_main.run @@ main ()
