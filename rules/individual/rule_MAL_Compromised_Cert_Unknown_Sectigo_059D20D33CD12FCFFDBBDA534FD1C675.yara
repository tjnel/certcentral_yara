import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_059D20D33CD12FCFFDBBDA534FD1C675 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-27"
      version             = "1.0"

      hash                = "00247c4c6aa56c58e4661317a7c4253245d8280d1d07502c9cb0b23d675edf3f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "万宁市领新创维工程有限公司"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "05:9d:20:d3:3c:d1:2f:cf:fd:bb:da:53:4f:d1:c6:75"
      cert_thumbprint     = "995ADC0A5AF35672C35E3B14C13DA808783D992E"
      cert_valid_from     = "2024-11-27"
      cert_valid_to       = "2025-11-27"

      country             = "CN"
      state               = "海南省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "914212005539498738"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "05:9d:20:d3:3c:d1:2f:cf:fd:bb:da:53:4f:d1:c6:75"
      )
}
