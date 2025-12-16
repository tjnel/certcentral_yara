import "pe"

rule MAL_Compromised_Cert_SolarMarker_Sectigo_2D88C0AF1FE2609961C171213C03BD23 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-10"
      version             = "1.0"

      hash                = "42788ef63efc2e74f7695cc618706e9f149a713b3241458503bf81290d8163ac"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Zhuzhou Lizhong Precision Manufacturing Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2d:88:c0:af:1f:e2:60:99:61:c1:71:21:3c:03:bd:23"
      cert_thumbprint     = "161A40889C28EBEDDADCDBD1EBCD29012540B927"
      cert_valid_from     = "2023-05-10"
      cert_valid_to       = "2024-05-09"

      country             = "CN"
      state               = "湖南省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91430200MA4L50L717"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2d:88:c0:af:1f:e2:60:99:61:c1:71:21:3c:03:bd:23"
      )
}
