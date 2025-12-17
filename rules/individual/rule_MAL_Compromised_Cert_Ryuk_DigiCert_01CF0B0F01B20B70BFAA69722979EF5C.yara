import "pe"

rule MAL_Compromised_Cert_Ryuk_DigiCert_01CF0B0F01B20B70BFAA69722979EF5C {
   meta:
      description         = "Detects Ryuk with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2019-12-27"
      version             = "1.0"

      hash                = "a9643eb83d509ad4eac20a2a89d8571f8d781979ad078e89f5b75b4bcb16f65e"
      malware             = "Ryuk"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PET PLUS PTY LTD"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "01:cf:0b:0f:01:b2:0b:70:bf:aa:69:72:29:79:ef:5c"
      cert_thumbprint     = "77FEB93900C2C699441F6117A7B3DE1CF3165074"
      cert_valid_from     = "2019-12-27"
      cert_valid_to       = "2021-01-06"

      country             = "AU"
      state               = "New South Wales"
      locality            = "LANE COVE"
      email               = "???"
      rdn_serial_number   = "000 343 457"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "01:cf:0b:0f:01:b2:0b:70:bf:aa:69:72:29:79:ef:5c"
      )
}
