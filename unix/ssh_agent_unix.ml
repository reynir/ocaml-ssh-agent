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
    Ssh_agent.Parse.unpack_any_response request response
  | { len; _ }, Ok _ ->
    Error "Additional data in reply"
  | _, Error e ->
    Error ("Parse error: " ^ e)
