import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00F284A0585FC0AF0D35AEE5177A7B3442 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-08"
      version             = "1.0"

      hash                = "9a5c14f2edefa00865e0cf3d86a3df4a59e2ec24efb73cabb4c11cf605cf133a"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cockos Incorporated"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "00:f2:84:a0:58:5f:c0:af:0d:35:ae:e5:17:7a:7b:34:42"
      cert_thumbprint     = "437196059B4553CE69BC94B0225D510AA4B586F0"
      cert_valid_from     = "2025-05-08"
      cert_valid_to       = "2025-12-18"

      country             = "US"
      state               = "New York"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "00:f2:84:a0:58:5f:c0:af:0d:35:ae:e5:17:7a:7b:34:42"
      )
}
