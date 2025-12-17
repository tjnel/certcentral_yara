import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7C9920452F17D886D0C4A9339F9EB792 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-07"
      version             = "1.0"

      hash                = "d2f02dd1dd325f3cca60672ac5b3d612db39e6139e2634f41890ce7e8c92f2a7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IC DIGITAL SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7c:99:20:45:2f:17:d8:86:d0:c4:a9:33:9f:9e:b7:92"
      cert_thumbprint     = "247D0C8B88667B382141F5045BFF63263EE3306B"
      cert_valid_from     = "2025-05-07"
      cert_valid_to       = "2026-05-07"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000481231"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7c:99:20:45:2f:17:d8:86:d0:c4:a9:33:9f:9e:b7:92"
      )
}
