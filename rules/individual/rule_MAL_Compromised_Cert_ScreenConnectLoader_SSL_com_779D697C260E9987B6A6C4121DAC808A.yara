import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_779D697C260E9987B6A6C4121DAC808A {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-05"
      version             = "1.0"

      hash                = "929a13cab29a6bb548e02e836af860a92eba8f9d490e390f49398a967034fb7c"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VELKA ENGINEERING LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "77:9d:69:7c:26:0e:99:87:b6:a6:c4:12:1d:ac:80:8a"
      cert_thumbprint     = "8031410747D5C91A2A92B45C8FC40C63322A79A0"
      cert_valid_from     = "2024-11-05"
      cert_valid_to       = "2025-11-05"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "C.47693"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "77:9d:69:7c:26:0e:99:87:b6:a6:c4:12:1d:ac:80:8a"
      )
}
