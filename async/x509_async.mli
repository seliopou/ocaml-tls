open Core
open Async

(** X.509 certificate handling using Async. *)

(** Private material: a certificate chain and a RSA private key. *)
type priv = X509.t list * Nocrypto.Rsa.priv

(** Authenticator. *)
type authenticator = X509.Authenticator.a

val private_of_pems :
     cert:Fpath.t
  -> priv_key:Fpath.t
  -> priv Or_error.t Deferred.t
(** [private_of_pems ~cert ~priv_key] is [priv], after reading the private key
   and certificate chain from the given PEM-encoded files. *)

val certs_of_pem : Fpath.t -> X509.t list Or_error.t Deferred.t
(** [certs_of_pem file] is [certificates], which are read from the PEM-encoded
   [file]. *)

val certs_of_pem_dir : ?ext:Fpath.ext -> Fpath.t -> X509.t list Deferred.t
(** [certs_of_pem_dir dir] is [certificates], which are read from all
   PEM-encoded files in [dir]. *)

val authenticator :
     [ `Ca_file of Fpath.t
     | `Ca_dir of Fpath.t
     | `Key_fingerprints of Nocrypto.Hash.hash * (string * Cstruct.t) list
     | `Hex_key_fingerprints of Nocrypto.Hash.hash * (string * string) list
     | `No_authentication ]
  -> authenticator Or_error.t Deferred.t
(** [authenticator methods] constructs an [authenticator] using the specified
   method and data. *)
