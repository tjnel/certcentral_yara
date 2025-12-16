import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0E6A6A2DF3B07B2438A0C96EF4413167 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-07"
      version             = "1.0"

      hash                = "e99896598b6c6df29735f4c0f08c99ff49275cba850c81c1249e865b6f4f8ba8"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Trinode Software Oy"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0e:6a:6a:2d:f3:b0:7b:24:38:a0:c9:6e:f4:41:31:67"
      cert_thumbprint     = "89EC5F7D5CC45309E8C0BC4B2038324A6E2F1279"
      cert_valid_from     = "2021-04-07"
      cert_valid_to       = "2022-04-11"

      country             = "FI"
      state               = "???"
      locality            = "Espoo"
      email               = "???"
      rdn_serial_number   = "3199637-3"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0e:6a:6a:2d:f3:b0:7b:24:38:a0:c9:6e:f4:41:31:67"
      )
}
