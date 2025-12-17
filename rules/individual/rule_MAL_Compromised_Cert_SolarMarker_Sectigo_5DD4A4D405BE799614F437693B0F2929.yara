import "pe"

rule MAL_Compromised_Cert_SolarMarker_Sectigo_5DD4A4D405BE799614F437693B0F2929 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-10"
      version             = "1.0"

      hash                = "13a1bead1187cbc6072c410501a417b812e82f1bbbf6a93deaab26ae5ea67628"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Changzhou Daqian Freighting Service Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5d:d4:a4:d4:05:be:79:96:14:f4:37:69:3b:0f:29:29"
      cert_thumbprint     = "8A7E0A1D10FBE17FD470364EE131B3BDA1381555"
      cert_valid_from     = "2023-08-10"
      cert_valid_to       = "2024-08-09"

      country             = "CN"
      state               = "江苏省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91320411137518732Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5d:d4:a4:d4:05:be:79:96:14:f4:37:69:3b:0f:29:29"
      )
}
