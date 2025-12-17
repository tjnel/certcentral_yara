import "pe"

rule MAL_Compromised_Cert_Investigating_Certum_622693C63F4274A602F102826119011E {
   meta:
      description         = "Detects Investigating with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-07-27"
      version             = "1.0"

      hash                = "03e9d7d08d45b44e92052a76ad963a587e5d451173347000e1a68eb304a340f6"
      malware             = "Investigating"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "UAB MN Technologijos"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "62:26:93:c6:3f:42:74:a6:02:f1:02:82:61:19:01:1e"
      cert_thumbprint     = "229A8D21E09426907D1B0A6AE80B2534A89CC580"
      cert_valid_from     = "2023-07-27"
      cert_valid_to       = "2024-07-26"

      country             = "LT"
      state               = "???"
      locality            = "Vilnius"
      email               = "???"
      rdn_serial_number   = "304869871"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "62:26:93:c6:3f:42:74:a6:02:f1:02:82:61:19:01:1e"
      )
}
