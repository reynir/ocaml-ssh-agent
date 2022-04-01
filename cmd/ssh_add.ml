let gen_key key_type bits =
  match key_type with
  | `RSA ->
    Ssh_agent.Privkey.Ssh_rsa (Mirage_crypto_pk.Rsa.generate ~bits ())
  | `ED25519 ->
    let priv, _pub = Mirage_crypto_ec.Ed25519.generate () in
    Ssh_agent.Privkey.Ssh_ed25519 priv

let main key_type bits key_comment =
  let () = Mirage_crypto_rng_unix.initialize () in
  let sock_path =
    match Sys.getenv "SSH_AUTH_SOCK" with
    | path -> path
    | exception Not_found -> failwith "$SSH_AUTH_SOCK not set" in
  let fd = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let () = Unix.connect fd Unix.(ADDR_UNIX sock_path) in
  let ic = Unix.in_channel_of_descr fd in
  let oc = Unix.out_channel_of_descr fd in
  let privkey = gen_key key_type bits in
  let req = Ssh_agent.Ssh_agentc_add_identity { privkey; key_comment } in
  match Ssh_agent_unix.request (ic, oc) req with
  | Ok Ssh_agent.Ssh_agent_success ->
    print_endline "Key successfully added!"
  | Ok Ssh_agent.Ssh_agent_failure ->
    print_endline "Ssh-agent reported failure"
  | Error e ->
    print_endline ("Error: " ^ e)

open Cmdliner

let bits =
  let doc = Arg.info ~doc:"Number of bits in the key to create (only applicable for RSA keys)" ["b"; "bits"] in
  Arg.(value & opt int 2048 doc)

let key_comment =
  let doc = Arg.info ~doc:"Key comment"  ["c"] in
  Arg.(value & opt string "Dummy key generated by OCaml" doc)

let key_type =
  let doc = Arg.info ~doc:"Key type" ["t"] in
  Arg.(value & opt (enum ["rsa", `RSA; "ed25519", `ED25519]) `RSA doc)

let () = 
  let term =
    Cmd.v (Cmd.info "ssh-add" ~version:"0.1")
      Term.(const main $ key_type $ bits $ key_comment)
  in
  Cmd.eval term
  |> exit
