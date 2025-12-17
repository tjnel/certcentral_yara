import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0C6B875DE4F598244A6D6751ABFBDFBD {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-08-26"
      version             = "1.0"

      hash                = "f268491d2f7e9ab562a239ec56c4b38d669a7bd88181efb0bd89e450c68dd421"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Full Stack s. r. o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0c:6b:87:5d:e4:f5:98:24:4a:6d:67:51:ab:fb:df:bd"
      cert_thumbprint     = "160A9CF7400D11BEFFD349F47136264EE56B6686"
      cert_valid_from     = "2021-08-26"
      cert_valid_to       = "2022-08-24"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "53 958 748"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0c:6b:87:5d:e4:f5:98:24:4a:6d:67:51:ab:fb:df:bd"
      )
}
