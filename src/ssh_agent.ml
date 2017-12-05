include Types

module Parse = Parse
module Serialize = Serialize

let is_extension_request (type a) (req : a ssh_agent_request) =
  match req with
  | Ssh_agentc_extension _ -> true
  | _ -> false
