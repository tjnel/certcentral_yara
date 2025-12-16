import "pe"

rule MAL_Compromised_Cert_SolarMarker_Certum_6CE7A0C62F27FA98F78853E1AD11173F {
   meta:
      description         = "Detects SolarMarker with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-05-26"
      version             = "1.0"

      hash                = "e531f0ecc9731fc8ffc22f8bc24d7ef1f09a3d8cff3f1369e0010ea173eb593a"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "D&K ENGINEERING"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "6c:e7:a0:c6:2f:27:fa:98:f7:88:53:e1:ad:11:17:3f"
      cert_thumbprint     = "638DC7CD59F1D634C19E4FC2C41B38AE08A1D2E5"
      cert_valid_from     = "2021-05-26"
      cert_valid_to       = "2022-05-26"

      country             = "US"
      state               = "California"
      locality            = "SAN DIEGO"
      email               = "???"
      rdn_serial_number   = "799638700"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "6c:e7:a0:c6:2f:27:fa:98:f7:88:53:e1:ad:11:17:3f"
      )
}
