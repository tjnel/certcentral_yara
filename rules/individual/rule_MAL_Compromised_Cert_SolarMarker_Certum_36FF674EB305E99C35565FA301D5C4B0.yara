import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_36FF674EB305E99C35565FA301D5C4B0 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-02"
      version             = "1.0"

      hash                = "8e06c31285911c936425921ccf9f20107160174acd602cc7f2dd8ca677e8956d"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "OOO Sistema"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "36:ff:67:4e:b3:05:e9:9c:35:56:5f:a3:01:d5:c4:b0"
      cert_thumbprint     = "C301843CA390AED52C4C6D59EF3D125400F186FB"
      cert_valid_from     = "2020-12-02"
      cert_valid_to       = "2021-12-02"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1127747243062"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "36:ff:67:4e:b3:05:e9:9c:35:56:5f:a3:01:d5:c4:b0"
      )
}
