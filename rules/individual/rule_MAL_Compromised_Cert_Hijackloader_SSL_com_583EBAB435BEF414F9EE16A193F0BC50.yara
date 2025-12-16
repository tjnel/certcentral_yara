import "pe"

rule MAL_Compromised_Cert_Hijackloader_SSL_com_583EBAB435BEF414F9EE16A193F0BC50 {
   meta:
      description         = "Detects Hijackloader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-07"
      version             = "1.0"

      hash                = "7154f4838553869cdddb4938ee6953284439b6d98e7285f573a35ea36982ed09"
      malware             = "Hijackloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VERIDAN"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "58:3e:ba:b4:35:be:f4:14:f9:ee:16:a1:93:f0:bc:50"
      cert_thumbprint     = "5C9397B60D94CC8BA9ACA936B09760EC1D4AC719"
      cert_valid_from     = "2025-10-07"
      cert_valid_to       = "2026-10-07"

      country             = "FR"
      state               = "Île-de-France"
      locality            = "Paris"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "58:3e:ba:b4:35:be:f4:14:f9:ee:16:a1:93:f0:bc:50"
      )
}
