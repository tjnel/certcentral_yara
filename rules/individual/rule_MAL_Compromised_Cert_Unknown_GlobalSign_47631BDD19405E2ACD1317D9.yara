import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_47631BDD19405E2ACD1317D9 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-05"
      version             = "1.0"

      hash                = "9df67ae1ae2272e0046305f1e7736276bb96bb61b4e0870f87481edb3ec3e84a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTWARE EDUCATIONAL SYSTEMS, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:63:1b:dd:19:40:5e:2a:cd:13:17:d9"
      cert_thumbprint     = "0357E295E84C2DBDB5E717E545481E53D0E5D74E"
      cert_valid_from     = "2024-07-05"
      cert_valid_to       = "2025-07-06"

      country             = "US"
      state               = "Utah"
      locality            = "Pleasant Grove"
      email               = "???"
      rdn_serial_number   = "12830800-0160"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:63:1b:dd:19:40:5e:2a:cd:13:17:d9"
      )
}
