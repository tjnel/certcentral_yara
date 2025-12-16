import "pe"

rule MAL_Compromised_Cert_Gh0st_RAT_Sectigo_00FEF386AC9C1D8636CB370C8C247F44FA {
   meta:
      description         = "Detects Gh0st RAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-08"
      version             = "1.0"

      hash                = "8071c7b74e7ca2769f3746ec8cc007caee65474bb77808b7a84c84f877452605"
      malware             = "Gh0st RAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DAVINCI VISION LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fe:f3:86:ac:9c:1d:86:36:cb:37:0c:8c:24:7f:44:fa"
      cert_thumbprint     = "81458929D258DB62735B3A6D56577FED725C2A02"
      cert_valid_from     = "2024-05-08"
      cert_valid_to       = "2025-05-08"

      country             = "CN"
      state               = "香港特别行政区"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "73087152"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fe:f3:86:ac:9c:1d:86:36:cb:37:0c:8c:24:7f:44:fa"
      )
}
