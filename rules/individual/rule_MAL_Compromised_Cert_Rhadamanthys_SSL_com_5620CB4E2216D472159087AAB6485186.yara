import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_5620CB4E2216D472159087AAB6485186 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-18"
      version             = "1.0"

      hash                = "314653180866938ffb3e125a8e8b3e3c4e4c06159ea3a8343fc083fbf45c776e"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Atlas Care Homes Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "56:20:cb:4e:22:16:d4:72:15:90:87:aa:b6:48:51:86"
      cert_thumbprint     = "BD5D24BB7161FD8104FC82A566B0BCE95CA6689D"
      cert_valid_from     = "2024-12-18"
      cert_valid_to       = "2025-12-18"

      country             = "GB"
      state               = "???"
      locality            = "Newcastle-Upon-Tyne"
      email               = "???"
      rdn_serial_number   = "09273411"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "56:20:cb:4e:22:16:d4:72:15:90:87:aa:b6:48:51:86"
      )
}
