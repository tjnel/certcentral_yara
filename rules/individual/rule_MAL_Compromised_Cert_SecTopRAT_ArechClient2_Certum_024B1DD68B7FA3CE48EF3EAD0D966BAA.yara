import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_Certum_024B1DD68B7FA3CE48EF3EAD0D966BAA {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-13"
      version             = "1.0"

      hash                = "28907701949c43559e5dfe1fed791b19bfa9f7009a171945dcd4d4b49f9cddd2"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Beijing Hairun Hongyuan Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "02:4b:1d:d6:8b:7f:a3:ce:48:ef:3e:ad:0d:96:6b:aa"
      cert_thumbprint     = "D439421448315B3813E783F8F9D6FBDFA6CE5A2F"
      cert_valid_from     = "2024-09-13"
      cert_valid_to       = "2025-09-13"

      country             = "CN"
      state               = "Beijing"
      locality            = "Beijing"
      email               = "???"
      rdn_serial_number   = "91110115596071474K"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "02:4b:1d:d6:8b:7f:a3:ce:48:ef:3e:ad:0d:96:6b:aa"
      )
}
