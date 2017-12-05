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
    let open Ssh_agent in
    let success_or_fail (resp : Ssh_agent.any_ssh_agent_response)
      : ([`Ssh_agentc_successable] Ssh_agent.ssh_agent_response, string) result =
      match resp with
      | Any_response (Ssh_agent_success as r) -> Ok r
      | Any_response (Ssh_agent_failure as r) -> Ok r
      | Any_response _ -> Error "Illegal response type"
    in
    begin match request with
     | Ssh_agent.Ssh_agentc_request_identities ->
       begin match (response : any_ssh_agent_response) with
         | Any_response (Ssh_agent_identities_answer _ as r) ->
           Ok r
         | Any_response (Ssh_agent_failure as r) ->
           Ok r
         | _ ->
           Error "Illegal response type"
       end
     | Ssh_agent.Ssh_agentc_sign_request (_,_,_) ->
       begin match response with
         | Any_response (Ssh_agent_sign_response _ as r) ->
           Ok r
         | Any_response (Ssh_agent_failure as r) ->
           Ok r
         | _ ->
           Error "Illegal response type"
       end
     | Ssh_agent.Ssh_agentc_extension _ ->
       begin match response with
         | Any_response (Ssh_agent_extension_failure as r) ->
           Ok r
         | Any_response (Ssh_agent_extension_success _ as r) ->
           Ok r
         | Any_response (Ssh_agent_failure as r) ->
           Ok r
         | _ ->
           Error "Illegal response type"
       end
     | Ssh_agent.Ssh_agentc_add_identity _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_remove_identity _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_remove_all_identities -> success_or_fail response
     | Ssh_agent.Ssh_agentc_add_smartcard_key _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_remove_smartcard_key _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_lock _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_unlock _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_add_id_constrained _ -> success_or_fail response
     | Ssh_agent.Ssh_agentc_add_smartcard_key_constrained _ -> success_or_fail response
    end
  | { len; _ }, Ok _ ->
    Error "Additional data in reply"
  | _, Error e ->
    Error ("Parse error: " ^ e)
