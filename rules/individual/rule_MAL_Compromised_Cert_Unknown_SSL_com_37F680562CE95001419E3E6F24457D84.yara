import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_37F680562CE95001419E3E6F24457D84 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-12"
      version             = "1.0"

      hash                = "0ec514bfafb165859fa07f3a06620b65c89680a901cd9ff010f7ffe7f5e875d6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "REAL GAMES DEVELOPMENT LTDA"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "37:f6:80:56:2c:e9:50:01:41:9e:3e:6f:24:45:7d:84"
      cert_thumbprint     = "C828EA8B16ACA73ACA00212A4548CF6A29FC4984"
      cert_valid_from     = "2025-02-12"
      cert_valid_to       = "2026-02-12"

      country             = "BR"
      state               = "RIO GRANDE DO NORTE"
      locality            = "PARNAMIRIM"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "37:f6:80:56:2c:e9:50:01:41:9e:3e:6f:24:45:7d:84"
      )
}
