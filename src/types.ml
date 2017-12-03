type ssh_agent_request_type = [
  | `Ssh_agentc_request_identities
  | `Ssh_agentc_sign_request
  | `Ssh_agentc_add_identity
  | `Ssh_agentc_remove_identity
  | `Ssh_agentc_remove_all_identities
  | `Ssh_agentc_add_smartcard_key
  | `Ssh_agentc_remove_smartcard_key
  | `Ssh_agentc_lock
  | `Ssh_agentc_unlock
  | `Ssh_agentc_add_id_constrained
  | `Ssh_agentc_add_smartcard_key_constrained
  | `Ssh_agentc_extension
]

type _ ssh_agent_request =
  | Ssh_agentc_request_identities :
      [`Ssh_agentc_request_identities] ssh_agent_request
  | Ssh_agentc_sign_request :
      Pubkey.t * string * Protocol_number.sign_flag list
    -> [`Ssh_agentc_sign_request] ssh_agent_request
  | Ssh_agentc_add_identity :
      { privkey : Privkey.t; key_comment : string }
    -> [`Ssh_agentc_add_identity] ssh_agent_request
  | Ssh_agentc_remove_identity :
      Pubkey.t
    -> [`Ssh_agentc_remove_identity] ssh_agent_request
  | Ssh_agentc_remove_all_identities :
      [`Ssh_agentc_remove_all_identities] ssh_agent_request
  | Ssh_agentc_add_smartcard_key :
      { smartcard_id : string; smartcard_pin : string }
    -> [`Ssh_agentc_add_smartcard_key] ssh_agent_request
  | Ssh_agentc_remove_smartcard_key :
      { smartcard_reader_id : string; smartcard_reader_pin : string }
    -> [`Ssh_agentc_remove_smartcard_key] ssh_agent_request
  | Ssh_agentc_lock :
      string
    -> [`Ssh_agentc_lock] ssh_agent_request
  | Ssh_agentc_unlock :
      string
    -> [`Ssh_agentc_unlock] ssh_agent_request
  | Ssh_agentc_add_id_constrained :
      { key_type : string; key_contents : string;
        key_comment : string; key_constraints : Protocol_number.key_constraint list }
    -> [`Ssh_agentc_add_id_constrained] ssh_agent_request
  | Ssh_agentc_add_smartcard_key_constrained :
      { smartcard_id : string; smartcard_pin : string;
        smartcard_constraints : Protocol_number.key_constraint list }
    -> [`Ssh_agentc_add_smartcard_key_constrained] ssh_agent_request
  | Ssh_agentc_extension :
      { extension_type : string; extension_contents : string }
    -> [`Ssh_agentc_extension] ssh_agent_request
  (** extension type * extension contents *)

type any_ssh_agent_request =
  Any_request : 'a ssh_agent_request -> any_ssh_agent_request

type _ ssh_agent_response =
  | Ssh_agent_failure : ssh_agent_request_type ssh_agent_response
  | Ssh_agent_success : ssh_agent_request_type ssh_agent_response
        (* TODO: refine when success can happen *)
  | Ssh_agent_extension_failure : [`Ssh_agentc_extension] ssh_agent_response
  | Ssh_agent_identities_answer : Pubkey.identity list
    -> [`Ssh_agentc_request_identities] ssh_agent_response
  | Ssh_agent_sign_response : string
    -> [`Ssh_agentc_sign_request] ssh_agent_response

type any_ssh_agent_response =
  Any_response : 'a ssh_agent_response -> any_ssh_agent_response
