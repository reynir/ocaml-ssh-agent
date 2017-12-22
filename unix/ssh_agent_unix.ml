let request ((ic, oc) : in_channel * out_channel)
    (type a)
    (request : a Ssh_agent.ssh_agent_request)
  : (a Ssh_agent.ssh_agent_response, string) result =
  let () =
    let buf = Faraday.create 1024 in
    Ssh_agent.Serialize.write_ssh_agent_request buf request;
    output_string oc (Faraday.serialize_to_string buf);
    flush oc in
  match Angstrom_unix.parse
          (Ssh_agent.Parse.ssh_agent_message ~extension:(Ssh_agent.is_extension_request request))
          ic with
  | { len = 0; _ }, Ok response ->
    Ssh_agent.unpack_any_response request response
  | { len; _ }, Ok _ ->
    Error "Additional data in reply"
  | _, Error e ->
    Error ("Parse error: " ^ e)

let rec accept (sock_fd : Unix.file_descr)
    (handler : Ssh_agent.request_handler) =
  let (fd, sockaddr) = Unix.accept sock_fd in
  let ic = Unix.in_channel_of_descr fd
  and oc = Unix.out_channel_of_descr fd in
  let rec loop () =
    match Angstrom_unix.parse Ssh_agent.Parse.ssh_agentc_message ic with
    | { len = 0; _ }, Ok (Ssh_agent.Any_request request) ->
      let response = handler.handle request in
      let buf = Faraday.create 1024 in
      let () = Ssh_agent.Serialize.write_ssh_agent_response buf response in
      let s = Faraday.serialize_to_string buf in
      let () = output_string oc s in
      let () = flush oc in
      loop ()
    | { len; _ }, Ok _ ->
      Printf.eprintf "Error: Additional data in request\n%!";
      Unix.close fd
    | _, Error e ->
      Printf.eprintf "Error: %s\n%!" e;
      Unix.close fd
  in
  loop ();
  accept sock_fd handler
