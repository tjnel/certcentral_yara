import "pe"

rule MAL_Compromised_Cert_PureHVNC_SSL_com_7EBAD9C6708D4A8E7673717C7D99E4CF {
   meta:
      description         = "Detects PureHVNC with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-20"
      version             = "1.0"

      hash                = "68eee73b68add553dcac41be42b0f41159d4fb02335ef4a3813efad8ff64d1f6"
      malware             = "PureHVNC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ferratum Capital Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7e:ba:d9:c6:70:8d:4a:8e:76:73:71:7c:7d:99:e4:cf"
      cert_thumbprint     = "223AC26A72792ACCA517AD143EFFE4E0E0FC5762"
      cert_valid_from     = "2025-08-20"
      cert_valid_to       = "2026-08-20"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7e:ba:d9:c6:70:8d:4a:8e:76:73:71:7c:7d:99:e4:cf"
      )
}
