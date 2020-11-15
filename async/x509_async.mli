open Core
open Async

(** X.509 certificate handling using Async. *)

(** Private material: a certificate chain and a RSA private key. *)
type priv = X509.Certificate.t list * Mirage_crypto_pk.Rsa.priv

(** Authenticator. *)
type authenticator = X509.Authenticator.t

val private_of_pems :
     cert:Filename.t
  -> priv_key:Filename.t
  -> priv Or_error.t Deferred.t
(** [private_of_pems ~cert ~priv_key] is [priv], after reading the private key
   and certificate chain from the given PEM-encoded files. *)

val certs_of_pem : Filename.t -> X509.Certificate.t list Or_error.t Deferred.t
(** [certs_of_pem file] is [certificates], which are read from the PEM-encoded
   [file]. *)

val certs_of_pem_dir
  :  ?ext:string
  ->  Filename.t
  -> X509.Certificate.t list Or_error.t Deferred.t
(** [certs_of_pem_dir dir] is [certificates], which are read from all
   PEM-encoded files in [dir]. *)

module Auth_method : sig
  module Fingerprints_by_domain : sig
    type 'a t = ([`host] Domain_name.t, 'a) List.Assoc.t
  end

  type t =
    | Ca_file of Filename.t
    | Ca_dir of Filename.t
    | Key_fingerprints of Mirage_crypto.Hash.hash * Cstruct.t Fingerprints_by_domain.t
    | Hex_key_fingerprints of Mirage_crypto.Hash.hash * string Fingerprints_by_domain.t
    | Cert_fingerprints of Mirage_crypto.Hash.hash * Cstruct.t Fingerprints_by_domain.t
    | Hex_cert_fingerprints of Mirage_crypto.Hash.hash * string Fingerprints_by_domain.t
end

val authenticator
  :  ?hash_whitelist:Mirage_crypto.Hash.hash list
  -> ?crls:Filename.t
  -> Auth_method.t
  -> authenticator Or_error.t Deferred.t
(** [authenticator methods] constructs an [authenticator] using the specified
   method and data. *)
