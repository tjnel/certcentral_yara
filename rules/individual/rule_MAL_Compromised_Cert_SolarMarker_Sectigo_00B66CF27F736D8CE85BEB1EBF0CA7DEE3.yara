import "pe"

rule MAL_Compromised_Cert_SolarMarker_Sectigo_00B66CF27F736D8CE85BEB1EBF0CA7DEE3 {
   meta:
      description         = "Detects SolarMarker with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-18"
      version             = "1.0"

      hash                = "278ec8f7a0cd969ebb84e72f60f19bb6f6fd6f7268ebe68245c46e6de2a43cf1"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "九江绿洲环境技术有限公司"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b6:6c:f2:7f:73:6d:8c:e8:5b:eb:1e:bf:0c:a7:de:e3"
      cert_thumbprint     = "13463D6E9AE08847E00EE54DF25497A545525698"
      cert_valid_from     = "2023-05-18"
      cert_valid_to       = "2024-05-17"

      country             = "CN"
      state               = "江西省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91360429MA3AECHY7X"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b6:6c:f2:7f:73:6d:8c:e8:5b:eb:1e:bf:0c:a7:de:e3"
      )
}
