import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_00E1911FCBC51E02B812F1C133297827 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "72893e08228f628e1b6f23db775182038bb7a6862ac1d6d9f62a4926dd193fc3"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "It-Rex Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "00:e1:91:1f:cb:c5:1e:02:b8:12:f1:c1:33:29:78:27"
      cert_thumbprint     = "4E26CAE8B53F3185945BE3740D2321601ED00A81"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-08"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "3254547-8"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "00:e1:91:1f:cb:c5:1e:02:b8:12:f1:c1:33:29:78:27"
      )
}
