import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_4BC686E2CD8CBD3B83A75FC82D509D91 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "328a8fb3ff41093c3b3352a6b3771e1d3351a04861ee73c7260ecb0e84aa51ff"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GENERAL PLASTICS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4b:c6:86:e2:cd:8c:bd:3b:83:a7:5f:c8:2d:50:9d:91"
      cert_thumbprint     = "77EA92F19B867DFFA05AEF22190BF261B1423A68"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2026-10-03"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4b:c6:86:e2:cd:8c:bd:3b:83:a7:5f:c8:2d:50:9d:91"
      )
}
