import "pe"

rule MAL_Compromised_Cert_Patchwork_SSL_com_35483C93453F1FD87066ABC2075FA85B {
   meta:
      description         = "Detects Patchwork with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-30"
      version             = "1.0"

      hash                = "54fb4b99a4a45338809ee58a3ee43bf0bd9cb97b356c466cd19a87497f216985"
      malware             = "Patchwork"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BPM Micro ApS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "35:48:3c:93:45:3f:1f:d8:70:66:ab:c2:07:5f:a8:5b"
      cert_thumbprint     = "61BF6497E36516857FCC89508C644B6123E5D0BA"
      cert_valid_from     = "2025-05-30"
      cert_valid_to       = "2026-05-30"

      country             = "DK"
      state               = "Hovedstaden"
      locality            = "Frederiksberg C"
      email               = "???"
      rdn_serial_number   = "39746875"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "35:48:3c:93:45:3f:1f:d8:70:66:ab:c2:07:5f:a8:5b"
      )
}
