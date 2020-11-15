open Core
open Async

type priv = X509.Certificate.t list * Mirage_crypto_pk.Rsa.priv

type authenticator = X509.Authenticator.t

let read_dir path =
  Sys.ls_dir path >>| List.map ~f:(Filename.concat path)

let read_file path =
  Monitor.try_with ~rest:`Raise ~run:`Now (fun () ->
    let%map contents = Reader.file_contents path  in
    Cstruct.of_string contents)
  >>| function
  | Ok v -> Ok v
  | Error exn ->
    Or_error.error (sprintf "Failed to load file %s" path) exn Exn.sexp_of_t

let private_of_pems ~cert ~priv_key =
  let open Deferred.Or_error.Let_syntax in
  let%bind (cert : X509.Certificate.t List.t) =
    let%bind cert = read_file cert  in
    match X509.Certificate.decode_pem_multiple cert with
    | Ok cs -> return cs
    | Error (`Msg msg) ->
      Deferred.return
        (Or_error.error_s [%message "failed to parse certificates" (msg : string)])
  and pk =
    let%bind pk = read_file priv_key  in
    match X509.Private_key.decode_pem pk with
    | Ok (`RSA key) -> return key
    | Error (`Msg msg) ->
      Deferred.return
        (Or_error.error_s [%message "failed to parse private key" (msg : string)])
  in
  return (cert, pk)
;;

let certs_of_pem path =
  let open Deferred.Or_error.Let_syntax in
  let%bind certs = read_file path in
  X509.Certificate.decode_pem_multiple certs
  |> Result.map_error ~f:(fun (`Msg msg) ->
      Error.create_s [%message "failed to parse certificates" (msg : string)])
  |> Deferred.return
;;

let matches_extension ~ext:needle filename =
  let _, extension = Filename.split_extension filename in
  match extension with
  | None -> false
  | Some extension -> String.equal extension needle
;;

let certs_of_pem_dir ?(ext = "crt") path =
  let%bind files = read_dir path in
  List.filter files ~f:(matches_extension ~ext)
  |> Deferred.Or_error.List.concat_map ~how:`Parallel ~f:certs_of_pem
;;

let crl_of_pem path =
  let open Deferred.Or_error.Let_syntax in
  let%bind data = read_file path in
  X509.CRL.decode_der data
  |> Result.map_error ~f:(fun (`Msg msg) ->
      Error.create_s [%message "failed to parse CRL" (msg : string)])
  |> Deferred.return
;;

let crls_of_pem_dir path =
  let%bind files  = read_dir path in
  List.filter files ~f:(matches_extension ~ext:"crt")
  |> Deferred.Or_error.List.map ~how:`Parallel ~f:crl_of_pem
;;

let authenticator ?hash_whitelist ?crls meth =
  let time () =
    Synchronous_time_source.wall_clock ()
    |> Synchronous_time_source.now
    |> Time_ns.to_int_ns_since_epoch
    |> Ptime.Span.of_int_s |> Ptime.of_span
    |> Option.value_exn ~message:"Invalid time value"
    |> Some
  in
  let open Deferred.Or_error.Let_syntax in
  let of_cas cas =
    let%map crls =
      match crls with
      | None -> return None
      | Some path ->
        let%map crls = crls_of_pem_dir path in
        Some crls
    in
    X509.Authenticator.chain_of_trust ?hash_whitelist ?crls ~time cas
  and dotted_hex_to_cs hex =
    Cstruct.of_hex (String.tr ~target:':' ~replacement:' ' hex)
  and fingerp hash fingerprints =
    X509.Authenticator.server_key_fingerprint ~time ~hash ~fingerprints
  and cert_fingerp hash fingerprints =
    X509.Authenticator.server_cert_fingerprint ~time ~hash ~fingerprints
  in
  match meth with
  | `Ca_file path -> certs_of_pem path >>= of_cas
  | `Ca_dir path  -> certs_of_pem_dir path >>= of_cas
  | `Key_fingerprints (hash, fps) -> return (fingerp hash fps)
  | `Hex_key_fingerprints (hash, fps) ->
    let fps = List.map fps ~f:(fun (n, v) -> (n, dotted_hex_to_cs v)) in
    return (fingerp hash fps)
  | `Cert_fingerprints (hash, fps) -> return (cert_fingerp hash fps)
  | `Hex_cert_fingerprints (hash, fps) ->
    let fps = List.map fps ~f:(fun (n, v) -> (n, dotted_hex_to_cs v)) in
    return (cert_fingerp hash fps)
