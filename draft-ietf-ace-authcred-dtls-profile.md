---
v: 3

title: Additional Formats of Authentication Credentials for the Datagram Transport Layer Security (DTLS) Profile for Authentication and Authorization for Constrained Environments (ACE)
abbrev: Authentication Credentials DTLS profile
docname: draft-ietf-ace-authcred-dtls-profile-latest

# stand_alone: true

ipr: trust200902
area: Security
wg: ACE Working Group
kw: Internet-Draft
cat: std
submissiontype: IETF
updates: 9202

coding: utf-8

author:
      -
        ins: M. Tiloca
        name: Marco Tiloca
        org: RISE AB
        street: Isafjordsgatan 22
        city: Kista
        code: SE-164 40
        country: Sweden
        email: marco.tiloca@ri.se
      -
        name: John Preuß Mattsson
        initials: J
        surname: Preuß Mattsson
        org: Ericsson AB
        city: Stockholm
        code: SE-164 80
        country: Sweden
        email: john.mattsson@ericsson.com

normative:
  I-D.ietf-cose-cbor-encoded-cert:
  I-D.ietf-ace-edhoc-oscore-profile:
  RFC3986:
  RFC5280:
  RFC6347:
  RFC6749:
  RFC6818:
  RFC7250:
  RFC7252:
  RFC8323:
  RFC8392:
  RFC9549:
  RFC8446:
  RFC8610:
  RFC8747:
  RFC8949:
  RFC9052:
  RFC9053:
  RFC9147:
  RFC9200:
  RFC9201:
  RFC9202:
  RFC9430:
  RFC9598:
  RFC9608:
  RFC9618:
  RFC9679:
  SHA-256:
    author:
      org: NIST
    title: Secure Hash Standard
    seriesinfo: FIPS 180-3
    date: 2008-10
    target: http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf

informative:
  RFC6091:

entity:
  SELF: "[RFC-XXXX]"

--- abstract

This document updates the Datagram Transport Layer Security (DTLS) profile for Authentication and Authorization for Constrained Environments (ACE). In particular, it specifies the use of additional formats of authentication credentials for establishing a DTLS session, when peer authentication is based on asymmetric cryptography. Therefore, this document updates RFC 9202. What is defined in this document is seamlessly applicable also if the profile uses Transport Layer Security (TLS) instead, as defined in RFC 9430.


--- middle

# Introduction # {#intro}

The Authentication and Authorization for Constrained Environments (ACE) framework {{RFC9200}} defines an architecture to enforce access control for constrained devices. A client (C) requests an evidence of granted permissions from an authorization server (AS) in the form of an access token, then uploads the access token to the target resource server (RS), and finally accesses protected resources at RS according to what is specified in the access token.

The framework has as main building blocks the OAuth 2.0 framework {{RFC6749}}, the Constrained Application Protocol (CoAP) {{RFC7252}} for message transfer, Concise Binary Object Representation (CBOR) {{RFC8949}} for compact encoding, and CBOR Object Signing and Encryption (COSE) {{RFC9052}}{{RFC9053}} for self-contained protection of access tokens.

Separate profile documents define in detail how the participants in the ACE architecture communicate, especially as to the security protocols that they use. In particular, the ACE profile defined in {{RFC9202}} specifies how Datagram Transport Layer Security (DTLS) {{RFC6347}}{{RFC9147}} is used to protect communications with transport-layer security in the ACE architecture. The profile has also been extended in {{RFC9430}}, in order to allow the alternative use of Transport Layer Security (TLS) {{RFC8446}} when CoAP is transported over TCP or WebSockets {{RFC8323}}.

The DTLS profile {{RFC9202}} allows C and RS to establish a DTLS session with peer authentication based on symmetric or asymmetric cryptography. For the latter case, the profile defines an RPK mode (see {{Section 3.2 of RFC9202}}), where authentication relies on the public keys of the two peers as raw public keys {{RFC7250}}.

That is, C specifies its public key to the AS when requesting an access token, and the AS provides such public key to the target RS as included in the issued access token. Upon issuing the access token, the AS also provides C with the public key of RS. Then, C and RS use their asymmetric keys when performing the DTLS handshake, as defined in {{RFC7250}}.

Per {{RFC9202}}, the DTLS profile admits only a COSE_Key object {{RFC9052}} as the format of authentication credentials to use for transporting the public keys of C and RS, as raw public keys. However, it is desirable to enable additional formats of authentication credentials, as enhanced raw public keys or as public certificates.

This document enables such additional formats in the DTLS profile, by defining how the public keys of C and RS can be specified by means of CBOR Web Token (CWT) Claims Sets (CCSs) {{RFC8392}}, or X.509 certificates {{RFC5280}}, or C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}.

This document also enables the DTLS profile to use the CWT Confirmation Method 'ckt' defined in {{RFC9679}} when using a COSE_Key object as raw public key, thus allowing to identifying the COSE_Key object by reference, alternatively to transporting it by value.

In particular, this document updates {{RFC9202}} as follows.

* {{sec-rpk-mode}} of this document extends the RPK mode defined in {{Section 3.2 of RFC9202}}, by enabling:

  - The use of CCSs to wrap the raw public keys of C and RS (see {{sec-rpk-mode-kccs}}).

  - The use of the CWT Confirmation Method 'ckt' to identify by reference a COSE_Key object used as authentication credential (see {{sec-rpk-mode-ckt}}).

* {{sec-cert-mode}} of this document defines a new certificate mode, which enables the use of X.509 or C509 certificates to specify the public keys of C and RS. In either case, certificates can be transported by value or instead identified by reference.

When using the updated RPK mode, the raw public keys of C and RS do not have to be of the same format. That is, it is possible to have both public keys as a COSE_Key object or as a CCS, or instead one as a COSE_Key object while the other one as a CCS. When both raw public keys are COSE_Keys, it is possible to have both COSE_Keys transported by value, or both identified by reference, or one transported by value while the other one identified by reference.

When using the certificate mode, the certificates of C and RS do not have to be of the same format. That is, it is possible to have both as X.509 certificates, or both as C509 certificates, or one as an X.509 certificate while the other one as a C509 certificate. Furthermore, it is possible to have both certificates transported by value, or both identified by reference, or one transported by value while the other one identified by reference.

Also, the RPK mode and the certificate mode can be combined. That is, it is possible that one of the two authentication credentials is a certificate, while the other one is a raw public key.

When using the formats introduced in this document, authentication credentials are specified by means of the CWT Confirmation Methods "kccs", "x5bag", "x5chain", "x5t", "x5u", "c5b", "c5c", "c5t", and "c5u" that are defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

What is defined in this document is seamlessly applicable if TLS is used instead, as defined in {{RFC9430}}.

## Terminology ## {#terminology}

{::boilerplate bcp14-tagged}

Readers are expected to be familiar with the terms and concepts described in the ACE framework for Authentication and Authorization {{RFC9200}}{{RFC9201}} and its DTLS profile {{RFC9202}}, as well as with terms and concepts related to CBOR Web Tokens (CWTs) {{RFC8392}} and CWT Confirmation Methods {{RFC8747}}.

The terminology for entities in the considered architecture is defined in OAuth 2.0 {{RFC6749}}. In particular, this includes client (C), resource server (RS), and authorization server (AS).

Readers are also expected to be familiar with the terms and concepts related to CoAP {{RFC7252}}, CBOR {{RFC8949}}, Concise Data Definition Language (CDDL) {{RFC8610}}, COSE {{RFC9052}}{{RFC9053}}, the DTLS protocol suite {{RFC6347}}{{RFC9147}}, and the use of raw public keys in DTLS {{RFC7250}}.

Note that the term "endpoint" is used here following its OAuth definition, aimed at denoting resources such as /token and /introspect at the AS, and /authz-info at RS. This document does not use the CoAP definition of "endpoint", which is "An entity participating in the CoAP protocol."

This document also refers to the term "authentication credential", which denotes the information associated with an entity, including that entity's public key and parameters associated with the public key. Examples of authentication credentials are CWT Claims Sets (CCSs) {{RFC8392}}, X.509 certificates {{RFC5280}}, and C509 certificates {{I-D.ietf-cose-cbor-encoded-cert}}.

Examples throughout this document are expressed in CBOR diagnostic notation as defined in {{Section 8 of RFC8949}} and {{Appendix G of RFC8610}}. Diagnostic notation comments are often used to provide a textual representation of the parameters' keys and values.

In the CBOR diagnostic notation used in this document, constructs of the form e'SOME_NAME' are replaced by the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. For example, {e'x5chain' : h'3081...cb02'} stands for {6 : h'3081...cb02'}.

Note to RFC Editor: Please delete the paragraph immediately preceding this note. Also, in the CBOR diagnostic notation used in this document, please replace the constructs of the form e'SOME_NAME' with the value assigned to SOME_NAME in the CDDL model shown in {{fig-cddl-model}} of {{sec-cddl-model}}. Finally, please delete this note.

# Updates to the RPK Mode # {#sec-rpk-mode}

This section updates the RPK mode defined in {{Section 3.2 of RFC9202}}, as detailed in the following {{sec-rpk-mode-kccs}} and {{sec-rpk-mode-ckt}}.

## Raw Public Keys as CCSs # {#sec-rpk-mode-kccs}

This section defines how the raw public key of C and RS can be provided as wrapped by a CCS {{RFC8392}}, instead of as a COSE_Key object {{RFC9052}}. Note that only the differences from {{RFC9202}} are compiled below.

If the raw public key of C is wrapped by a CCS, then the following applies.

* The payload of the Access Token Request (see {{Section 5.8.1 of RFC9200}}) is as defined in {{Section 3.2.1 of RFC9202}}, with the difference that the "req_cnf" parameter {{RFC9201}} MUST specify a "kccs" structure, with value a CCS specifying the public key of C that has to be bound to the access token.

  In particular, the CCS MUST include the "cnf" claim specifying the public key of C as a COSE_Key object, SHOULD include the "sub" claim specifying the subject name of C associated with the public key of C, and MAY include additional claims.

* The content of the access token that the AS provides to C in the Access Token Response (see {{Section 5.8.2 of RFC9200}}) is as defined in {{Section 3.2.1 of RFC9202}}, with the difference that the "cnf" claim of the access token MUST specify a "kccs" structure, with value a CCS specifying the public key of C that is bound to the access token.

  In particular, the CCS MUST include the "cnf" claim specifying the public key of C as a COSE_Key object, SHOULD include the "sub" claim specifying the subject name of C associated with the public key of C, and MAY include additional claims.

If the raw public key of RS is wrapped by a CCS, then the following applies.

* The payload of the Access Token Response is as defined in {{Section 3.2.1 of RFC9202}}, with the difference that the "rs_cnf" parameter {{RFC9201}} MUST specify a "kccs" structure, with value a CCS specifying the public key of RS.

  In particular, the CCS MUST include the "cnf" claim specifying the public key of RS as a COSE_Key object, SHOULD include the "sub" claim specifying the subject name of RS associated with the public key of RS, and MAY include additional claims.

For the "req_cnf" parameter of the Access Token Request, the "rs_cnf" parameter of the Access Token Response, and the "cnf" claim of the access token, the Confirmation Method "kccs" structure and its identifier are defined in {{I-D.ietf-ace-edhoc-oscore-profile}}.

It is not required that both public keys are wrapped by a CCS. That is, one of the two authentication credentials can be a CCS, while the other one can be a COSE_Key object transported by value as per {{Section 3.2 of RFC9202}} or identified by reference as per {{sec-rpk-mode-ckt}} of this document.

### Examples

{{fig-example-C-to-AS-ccs}} shows an example of Access Token Request from C to the AS.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       e'kccs' : {
         / sub / 2 : "42-50-31-FF-EF-37-32-39",
         / cnf / 8 : {
           / COSE_Key / 1 : {
             / kty /    1 : 2 / EC2 /,
             / crv /   -1 : 1 / P-256 /,
             / x /     -2 : h'd7cc072de2205bdc1537a543d53c60a6
                              acb62eccd890c7fa27c9e354089bbe13',
             / y /     -3 : h'f95e1d4b851a2cc80fff87d8e23f22af
                              b725d535e515d020731e79a3b4e47120'
           }
         }
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-ccs title="Access Token Request Example for RPK Mode, with the Public Key of C Wrapped by a CCS conveyed within \"req_cnf\""}

{{fig-example-AS-to-C-ccs}} shows an example of Access Token Response from the AS to C.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...643b',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's RPK in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       e'kccs' : {
         / sub / 2 : "AA-BB-CC-00-01-02-03-04",
         / cnf / 8 : {
           / COSE_Key / 1 : {
             / kty /  1 : 2 / EC2 /,
             / crv / -1 : 1 / P-256 /,
             / x /   -2 : h'bbc34960526ea4d32e940cad2a234148
                            ddc21791a12afbcbac93622046dd44f0',
             / y /   -3 : h'4519e257236b2a0ce2023f0931f1f386
                            ca7afda64fcde0108c224c51eabf6072'
           }
         }
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-ccs title="Access Token Response Example for RPK Mode, with the Public Key of RS Wrapped by a CCS, Conveyed within \"rs_cnf\""}

## Raw Public Keys as COSE\_Keys Identified by Reference # {#sec-rpk-mode-ckt}

As per {{Section 3.2 of RFC9202}}, COSE_Key objects {{RFC9052}} used as raw public keys are transported by value in the Access Token Request and Response messages, as well as within access tokens.

This section extends the DTLS profile by allowing to identifying those COSE_Key objects by reference, alternatively to transporting those by value. Note that only the differences from {{RFC9202}} are compiled below.

The following relies on the CWT Confirmation Method 'ckt' defined in {{RFC9679}}. When using a 'ckt' structure, this conveys the thumbprint of a COSE_Key object computed as per {{Section 3 of RFC9679}}. In particular, the used hash function MUST be SHA-256 {{SHA-256}}, which is mandatory to support when supporting COSE Key thumbprints.

If the raw public key of C is a COSE_Key object COSE_KEY_C and the intent is to identify it by reference, then the following applies.

* The payload of the Access Token Request (see {{Section 5.8.1 of RFC9200}}) is as defined in {{Section 3.2.1 of RFC9202}}, with the difference that the "req_cnf" parameter {{RFC9201}} MUST specify a "ckt" structure, with value the thumbprint of COSE_KEY_C.

* The content of the access token that the AS provides to C in the Access Token Response (see {{Section 5.8.2 of RFC9200}}) is as defined in {{Section 3.2.1 of RFC9202}}, with the difference that the "cnf" claim of the access token MUST specify a "ckt" structure, with value the thumbprint of COSE_KEY_C.

If the raw public key of RS is a COSE_Key object COSE_KEY_RS and the intent is to identify it by reference, then the following applies.

* The payload of the Access Token Response is as defined in {{Section 3.2.1 of RFC9202}}, with the difference that the "rs_cnf" parameter {{RFC9201}} MUST specify a "ckt" structure, with value the thumbprint of COSE_KEY_RS.

When both public keys are COSE_Keys, it is possible to have both COSE_Keys transported by value, or both identified by reference, or one transported by value while the other one identified by reference.

Note that the use of COSE Key thumbprints per {{RFC9679}} is applicable only to authentication credentials that are COSE_Key objects. That is, the 'ckt' structure MUST NOT be used to identify authentication credentials of other formats and that include a COSE_Key object as part of their content, such as CCSs as defined in {{sec-rpk-mode-kccs}}.

### Examples

{{fig-example-C-to-AS-ckt}} shows an example of Access Token Request from C to the AS.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       / ckt / 5 : h'd3550f1b5b763ee09d058fc7aef69900
                     1279903a4a15bdc3953d32b10f7cb8b1'
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-ckt title="Access Token Request Example for RPK Mode, with the Public Key of C as a COSE_Key Identified by Reference within \"req_cnf\""}

{{fig-example-AS-to-C-ckt}} shows an example of Access Token Response from the AS to C.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...643b',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's RPK in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       / ckt / 5 : h'db60f4d371fffac3e1040566154a5c36
                     1e0bf835a4ad4c58069cf6edc9ac58a3'
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-ckt title="Access Token Response Example for RPK Mode, with the Public Key of RS as a COSE_Key Identified by Reference within \"rs_cnf\""}

# Certificate Mode # {#sec-cert-mode}

This section defines a new certificate mode of the DTLS profile, which enables the use of public certificates to specify the public keys of C and RS. Compared to the RPK mode defined in {{Section 3.2 of RFC9202}} and extended in {{sec-rpk-mode}} of this document, the certificate mode displays the differences compiled below.

The authentication credential of C and/or RS is a public certificate, i.e., an X.509 certificate {{RFC5280}} or a C509 certificate {{I-D.ietf-cose-cbor-encoded-cert}}.

* The CWT Confirmation Methods "x5chain", "x5bag", "c5c", and "c5b" defined in {{I-D.ietf-ace-edhoc-oscore-profile}} are used to transport such authentication credentials by value.

* The CWT Confirmation Methods "x5t", "x5u", "c5t", and "c5u" defined in {{I-D.ietf-ace-edhoc-oscore-profile}} are used to identify such authentication credentials by reference.

If the authentication credential AUTH_CRED_C of C is a public certificate, then the following applies.

- The "req_cnf" parameter {{RFC9201}} of the Access Token Request (see {{Section 5.8.1 of RFC9200}}) specifies AUTH_CRED_C as follows.

  If AUTH_CRED_C is an X.509 certificate, the "req_cnf" parameter MUST specify:

  - An "x5chain" or "x5bag" structure, in case AUTH_CRED_C is transported by value within a certificate chain or a certificate bag, respectively; or

  - An "x5t" or "x5u" structure, in case AUTH_CRED_C is identified by reference through a hash value (a thumbprint) or a URI {{RFC3986}}, respectively.

  If AUTH_CRED_C is a C509 certificate, the "req_cnf" parameter MUST specify:

  - A "c5c" or "c5b" structure, in case AUTH_CRED_C is transported by value within a certificate chain or a certificate bag, respectively; or

  - A "c5t" or "c5u" structure, in case AUTH_CRED_C is identified by reference through a hash value (a thumbprint) or a URI {{RFC3986}}, respectively.

- The "cnf" claim of the access token that the AS provides to C in the Access Token Response (see {{Section 5.8.2 of RFC9200}}) specifies AUTH_CRED_C as follows.

  If AUTH_CRED_C is an X.509 certificate, the "cnf" claim MUST specify:

  - An "x5chain" or "x5bag" structure, in case AUTH_CRED_C is transported by value within a certificate chain or a certificate bag, respectively; or

  - An "x5t" or "x5u" structure, in case AUTH_CRED_C is identified by reference through a hash value (a thumbprint) or a URI {{RFC3986}}, respectively.

  If AUTH_CRED_C is a C509 certificate, the "cnf" claim MUST specify:

  - A "c5c" or "c5b" structure, in case AUTH_CRED_C is transported by value within a certificate chain or a certificate bag, respectively; or

  - A "c5t" or "c5u" structure, in case AUTH_CRED_C is identified by reference through a hash value (a thumbprint) or a URI {{RFC3986}}, respectively.

If the authentication credential AUTH_CRED_RS of RS is a public certificate, then the following applies.

- The "rs_cnf" parameter {{RFC9201}} of the Access Token Response specifies AUTH_CRED_RS as follows.

  If AUTH_CRED_RS is an X.509 certificate, the "rs_cnf" parameter MUST specify:

  - An "x5chain" or "x5bag" structure, in case AUTH_CRED_RS is transported by value within a certificate chain or a certificate bag, respectively; or

  - An "x5t" or "x5u" structure, in case AUTH_CRED_RS is identified by reference through a hash value (a thumbprint) or a URI {{RFC3986}}, respectively.

  If AUTH_CRED_RS is a C509 certificate, the "rs_cnf" parameter MUST specify:

  - A "c5c" or "c5b" structure, in case AUTH_CRED_RS is transported by value within a certificate chain or a certificate bag, respectively; or

  - A "c5t" or "c5u" structure, in case AUTH_CRED_RS is identified by reference through a hash value (a thumbprint) or a URI {{RFC3986}}, respectively.

For the "req_cnf" parameter of the Access Token Request, the "rs_cnf" parameter of the Access Token Response, and the "cnf" claim of the access token, the structures "x5bag", "x5chain", "x5t", "x5u", "c5b", "c5c", "c5t", and "c5u" are defined in {{I-D.ietf-ace-edhoc-oscore-profile}}, together with their identifiers.

When using either of the structures, the specified authentication credential is just the end-entity certificate.

As per {{RFC6347}} and {{RFC9147}}, a public certificate is specified in the Certificate message of the DTLS handshake. For X.509 certificates, the TLS Certificate Type is "X509", as defined in {{RFC6091}}. For C509 certificates, the TLS certificate type is "C509 Certificate", as defined in {{I-D.ietf-cose-cbor-encoded-cert}}.

It is not required that AUTH_CRED_C and AUTH_CRED_RS are both X.509 certificates or both C509 certificates. Also, it is not required that AUTH_CRED_C and AUTH_CRED_RS are both transported by value or both identified by reference.

Finally, one of the two authentication credentials can be a public certificate, while the other one can be a raw public key. This is consistent with the admitted, combined use of raw public keys and certificates, as discussed in {{Section 5.3 of RFC7250}}.

## Examples

{{fig-example-C-to-AS-x509}} shows an example of Access Token Request from C to the AS. In the example, C specifies its authentication credential by means of an "x5chain" structure, transporting by value only its own X.509 certificate.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       e'x5chain' : h'3081ee3081a1a003020102020462319ec430
                      0506032b6570301d311b301906035504030c
                      124544484f4320526f6f7420456432353531
                      39301e170d3232303331363038323433365a
                      170d3239313233313233303030305a302231
                      20301e06035504030c174544484f43205265
                      73706f6e6465722045643235353139302a30
                      0506032b6570032100a1db47b95184854ad1
                      2a0c1a354e418aace33aa0f2c662c00b3ac5
                      5de92f9359300506032b6570034100b723bc
                      01eab0928e8b2b6c98de19cc3823d46e7d69
                      87b032478fecfaf14537a1af14cc8be829c6
                      b73044101837eb4abc949565d86dce51cfae
                      52ab82c152cb02'
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-x509 title="Access Token Request Example for Certificate Mode with an X.509 Certificate as Authentication Credential of C, Transported by Value within \"req_cnf\""}

{{fig-example-AS-to-C-x509}} shows an example of Access Token Response from the AS to C. In the example, the AS specifies the authentication credential of RS by means of an "x5chain" structure, transporting by value only the X.509 certificate of RS.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...2fa6',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's X.509 certificate in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       e'x5chain' : h'3081ee3081a1a003020102020462319ea030
                      0506032b6570301d311b301906035504030c
                      124544484f4320526f6f7420456432353531
                      39301e170d3232303331363038323430305a
                      170d3239313233313233303030305a302231
                      20301e06035504030c174544484f4320496e
                      69746961746f722045643235353139302a30
                      0506032b6570032100ed06a8ae61a829ba5f
                      a54525c9d07f48dd44a302f43e0f23d8cc20
                      b73085141e300506032b6570034100521241
                      d8b3a770996bcfc9b9ead4e7e0a1c0db353a
                      3bdf2910b39275ae48b756015981850d27db
                      6734e37f67212267dd05eeff27b9e7a813fa
                      574b72a00b430b'
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-x509 title="Access Token Response Example for Certificate Mode with an X.509 Certificate as Authentication Credential of RS, Transported by Value within \"rs_cnf\""}

The following shows a variation of the two previous examples, where the same X.509 certificates are instead identified by reference.

{{fig-example-C-to-AS-x509-ref}} shows an example of Access Token Request from C to the AS. In the example, C specifies its authentication credential by means of an "x5t" structure, identifying by reference its own X.509 certificate.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       e'x5t' : [-15, h'79f2a41b510c1f9b']
       / SHA-2 256-bit Hash truncated to 64-bits /
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-x509-ref title="Access Token Request Example for Certificate Mode with an X.509 Certificate as Authentication Credential of C, Identified by Reference within \"req_cnf\""}

{{fig-example-AS-to-C-x509-ref}} shows an example of Access Token Response from the AS to C. In the example, the AS specifies the authentication credential of RS by means of an "x5t" structure, identifying by reference the X.509 certificate of RS.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...2fa6',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's X.509 certificate in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       e'x5t' : [-15, h'c24ab2fd7643c79f']
       / SHA-2 256-bit Hash truncated to 64-bits /
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-x509-ref title="Access Token Response Example for Certificate Mode with an X.509 Certificate as Authentication Credential of RS, Transported by Value within \"rs_cnf\""}

# Security Considerations # {#sec-security-considerations}

The security considerations from {{RFC9200}} and {{RFC9202}} apply to this document as well.

When using the CWT Confirmation Method 'ckt' for identifying by reference a COSE_Key object as a raw public key, the security considerations from {{RFC9679}} apply.

When using public certificates as authentication credentials, the security considerations from {{Section C.2 of RFC8446}} apply.

When using X.509 certificates as authentication credentials, the security considerations from {{RFC5280}}, {{RFC6818}}, {{RFC9598}}, {{RFC9549}}, {{RFC9608}}, and {{RFC9618}} apply.

When using C509 certificates as authentication credentials, the security considerations from {{I-D.ietf-cose-cbor-encoded-cert}} apply.

# IANA Considerations

This document has no actions for IANA.

--- back

# Examples with Hybrid Settings # {#ssec-example-hybrid}

This section provides additional examples where, within the same ACE execution workflow, C and RS use different formats of raw public keys (see {{ssec-example-hybrid-1}}), or different formats of certificates (see {{ssec-example-hybrid-2}}), or a combination of the RPK mode and certificate mode (see {{ssec-example-hybrid-3}}).

## RPK Mode (Raw Public Keys of Different Formats) # {#ssec-example-hybrid-1}

{{fig-example-C-to-AS-cose-key}} shows an example of Access Token Request from C to the AS, where the public key of C is conveyed as a COSE Key.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       / COSE_Key / 1 : {
         / kty /    1 : 2 / EC2 /,
         / crv /   -1 : 1 / P-256 /,
         / x /     -2 : h'd7cc072de2205bdc1537a543d53c60a6
                          acb62eccd890c7fa27c9e354089bbe13',
         / y /     -3 : h'f95e1d4b851a2cc80fff87d8e23f22af
                          b725d535e515d020731e79a3b4e47120'
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-cose-key title="Access Token Request Example for RPK Mode, with the Public Key of C Conveyed as a COSE Key within \"req_cnf\""}

{{fig-example-AS-to-C-ccs-2}} shows an example of Access Token Response from the AS to C, where the public key of RS is wrapped by a CCS.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...c41a',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's RPK in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       e'kccs' : {
         / sub / 2 : "DD-EE-FF-05-06-07-08-09",
         / cnf / 8 : {
           / COSE_Key / 1 : {
             / kty /  1 : 2 / EC2 /,
             / crv / -1 : 1 / P-256 /,
             / x /   -2 : h'ac75e9ece3e50bfc8ed6039988952240
                            5c47bf16df96660a41298cb4307f7eb6',
             / y /   -3 : h'6e5de611388a4b8a8211334ac7d37ecb
                            52a387d257e6db3c2a93df21ff3affc8'
           }
         }
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-ccs-2 title="Access Token Response Example for RPK Mode, with the Public Key of RS Wrapped by a CCS within \"rs_cnf\""}

## Certificate Mode (Certificates of Different Formats) # {#ssec-example-hybrid-2}

{{fig-example-C-to-AS-x509-2}} shows an example of Access Token Request from C to the AS. In the example, C specifies its authentication credential by means of an "x5chain" structure, transporting by value only its own X.509 certificate.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       e'x5chain' : h'308201383081dea003020102020301f50d30
                      0a06082a8648ce3d04030230163114301206
                      035504030c0b524643207465737420434130
                      1e170d3233303130313030303030305a170d
                      3236303130313030303030305a3022312030
                      1e06035504030c1730312d32332d34352d46
                      462d46452d36372d38392d41423059301306
                      072a8648ce3d020106082a8648ce3d030107
                      03420004b1216ab96e5b3b3340f5bdf02e69
                      3f16213a04525ed44450b1019c2dfd3838ab
                      ac4e14d86c0983ed5e9eef2448c6861cc406
                      547177e6026030d051f7792ac206a30f300d
                      300b0603551d0f040403020780300a06082a
                      8648ce3d0403020349003046022100d4320b
                      1d6849e309219d30037e138166f2508247dd
                      dae76cceea55053c108e90022100d551f6d6
                      0106f1abb484cfbe6256c178e4ac3314ea19
                      191e8b607da5ae3bda16'
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-x509-2 title="Access Token Request Example for Certificate Mode with an X.509 Certificate as Authentication Credential of C, Transported by Value within \"req_cnf\""}

{{fig-example-AS-to-C-x509}} shows an example of Access Token Response from the AS to C. In the example, the AS specifies the authentication credential of RS by means of a "c5c" structure, transporting by value only the C509 certificate of RS.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...2fa6',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's C509 certificate in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       e'c5c' : h'03487e7661d7b54e46328a23625553066243
                  41086b4578616d706c6520496e63096d6365
                  7274696669636174696f6e016a3830322e31
                  41522043411a5c52dc0cf68c236255530662
                  434105624c41086b6578616d706c6520496e
                  630963496f542266577431323334015821fd
                  c8b421f11c25e47e3ac57123bf2d9fdc494f
                  028bc351cc80c03f150bf50cff958a042101
                  5496600d8716bf7fd0e752d0ac760777ad66
                  5d02a0075468d16551f951bfc82a431d0d9f
                  08bc2d205b1160210503822082492b060104
                  01b01f0a014401020304005840c0d81996d2
                  507d693f3c48eaa5ee9491bda6db214099d9
                  8117c63b361374cd86a774989f4c321a5cf2
                  5d832a4d336a08ad67df20f1506421188a0a
                  de6d349236'
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-c509 title="Access Token Response Example for Certificate Mode with a C509 Certificate as Authentication Credential of RS, Transported by Value within \"rs_cnf\""}

## Combination of RPK Mode and Certificate Mode # {#ssec-example-hybrid-3}

{{fig-example-C-to-AS-ccs-2}} shows an example of Access Token Request from C to the AS, where the public key of C is wrapped by a CCS.

~~~~~~~~~~~
   POST coaps://as.example.com/token
   Content-Format: 19 (application/ace+cbor)
   Payload:
   {
     / grant_type / 33 : 2 / client_credentials /,
     / audience /    5 : "tempSensor4711",
     / req_cnf /     4 : {
       e'kccs' : {
         / sub / 2 : "55-11-44-AB-CD-EF-00-00",
         / cnf / 8 : {
           / COSE_Key / 1 : {
             / kty /    1 : 2 / EC2 /,
             / crv /   -1 : 1 / P-256 /,
             / x /     -2 : h'cd4177ba62433375ede279b5e18e8b91
                              bc3ed8f1e174474a26fc0edb44ea5373',
             / y /     -3 : h'a0391de29c5c5badda610d4e301eaaa1
                              8422367722289cd18cbe6624e89b9cfd'
           }
         }
       }
     }
   }
~~~~~~~~~~~
{: #fig-example-C-to-AS-ccs-2 title="Access Token Request Example for RPK Mode, with the Public Key of C Wrapped by a CCS within \"req_cnf\""}

{{fig-example-AS-to-C-x509-3}} shows an example of Access Token Response from the AS to C. In the example, the AS specifies the authentication credential of RS by means of an "x5chain" structure, transporting by value only the X.509 certificate of RS.

~~~~~~~~~~~
   2.01 Created
   Content-Format: 19 (application/ace+cbor)
   Max-Age: 3560
   Payload:
   {
     / access_token / 1 : h'd83dd083...0f7b',
       / (remainder of CWT omitted for brevity;
       CWT contains the client's X.509 certificate in the cnf claim) /
     / expires_in /   2 : 3600,
     / rs_cnf /      41 : {
       e'x5chain' : h'3082023d308201e2a00302010202087e7661
                      d7b54e4632300a06082a8648ce3d04030230
                      5d310b3009060355040613025553310b3009
                      06035504080c02434131143012060355040a
                      0c0b4578616d706c6520496e633116301406
                      0355040b0c0d63657274696669636174696f
                      6e3113301106035504030c0a3830322e3141
                      522043413020170d31393031333131313239
                      31365a180f39393939313233313233353935
                      395a305c310b300906035504061302555331
                      0b300906035504080c024341310b30090603
                      5504070c024c4131143012060355040a0c0b
                      6578616d706c6520496e63310c300a060355
                      040b0c03496f54310f300d06035504051306
                      5774313233343059301306072a8648ce3d02
                      0106082a8648ce3d03010703420004c8b421
                      f11c25e47e3ac57123bf2d9fdc494f028bc3
                      51cc80c03f150bf50cff958d75419d81a6a2
                      45dffae790be95cf75f602f9152618f816a2
                      b23b5638e59fd9a3818a3081873009060355
                      1d1304023000301d0603551d0e0416041496
                      600d8716bf7fd0e752d0ac760777ad665d02
                      a0301f0603551d2304183016801468d16551
                      f951bfc82a431d0d9f08bc2d205b1160300e
                      0603551d0f0101ff0404030205a0302a0603
                      551d1104233021a01f06082b060105050708
                      04a013301106092b06010401b43b0a010404
                      01020304300a06082a8648ce3d0403020349
                      003046022100c0d81996d2507d693f3c48ea
                      a5ee9491bda6db214099d98117c63b361374
                      cd86022100a774989f4c321a5cf25d832a4d
                      336a08ad67df20f1506421188a0ade6d3492
                      36'
     }
   }
~~~~~~~~~~~
{: #fig-example-AS-to-C-x509-3 title="Access Token Response Example for Certificate Mode with an X.509 Certificate as Authentication Credential of RS, Transported by Value within \"rs_cnf\""}

# CDDL Model # {#sec-cddl-model}
{:removeinrfc}

~~~~~~~~~~~~~~~~~~~~ CDDL
; CWT Confirmation Methods
x5chain = 6
x5t = 8
c5c = 10
kccs = 15
~~~~~~~~~~~~~~~~~~~~
{: #fig-cddl-model title="CDDL model" artwork-align="left"}

# Document Updates # {#sec-document-updates}
{:removeinrfc}

## Version -00 to -01 ## {#sec-00-01}

* Enabled use of COSE Keys identified by reference with a thumbprint.

* Changed CBOR abbreviations to not collide with existing codepoints.

* Fixes in the examples in CBOR diagnostic notation.

* Updated references.

* Editorial improvements.

# Acknowledgments # {#acknowledgments}
{:numbered="false"}

The authors sincerely thank {{{Rikard Höglund}}} and {{{Göran Selander}}} for their comments and feedback.

This work was supported by the Sweden's Innovation Agency VINNOVA within the EUREKA CELTIC-NEXT project CYPRESS; and by the H2020 project SIFIS-Home (Grant agreement 952652).
