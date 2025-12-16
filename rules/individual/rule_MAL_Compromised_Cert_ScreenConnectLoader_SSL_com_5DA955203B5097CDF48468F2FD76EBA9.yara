import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_5DA955203B5097CDF48468F2FD76EBA9 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-08"
      version             = "1.0"

      hash                = "a22675c9778b13172e932f28b17647ae80abb4bd95b6f47898a01f2da81ac18e"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Neurogenx LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5d:a9:55:20:3b:50:97:cd:f4:84:68:f2:fd:76:eb:a9"
      cert_thumbprint     = "BD064BAF13517C969B1C939BE7B7A14074B1ACA5"
      cert_valid_from     = "2025-09-08"
      cert_valid_to       = "2026-09-08"

      country             = "US"
      state               = "California"
      locality            = "Sacramento"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5d:a9:55:20:3b:50:97:cd:f4:84:68:f2:fd:76:eb:a9"
      )
}
