import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_0291C35AB6F0EC2F79C8F1CE5F37E776 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-02-08"
      version             = "1.0"

      hash                = "8447b77cc4b708ed9f68d0d71dd79f5e66fe27fedd081dcc1339b6d35c387725"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "OOO Ruvents"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "02:91:c3:5a:b6:f0:ec:2f:79:c8:f1:ce:5f:37:e7:76"
      cert_thumbprint     = "64272B0A1025EF13F3A7806E9A326B8FB7619B17"
      cert_valid_from     = "2021-02-08"
      cert_valid_to       = "2022-02-08"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1147746160320"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "02:91:c3:5a:b6:f0:ec:2f:79:c8:f1:ce:5f:37:e7:76"
      )
}
