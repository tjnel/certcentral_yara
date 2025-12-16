import "pe"

rule MAL_Compromised_Cert_Onyx_RMM_Sectigo_00C33C5E2FDC570E323B8EB3789C68B016 {
   meta:
      description         = "Detects Onyx RMM with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-07"
      version             = "1.0"

      hash                = "566a38f3244e8bb54ae80feb54928e39868f84ce838378e4f984eafbcf64a84f"
      malware             = "Onyx RMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chrissy's Credible Cleaning LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c3:3c:5e:2f:dc:57:0e:32:3b:8e:b3:78:9c:68:b0:16"
      cert_thumbprint     = "862937CFE306D2A83C146744AB6BE23A7F744977"
      cert_valid_from     = "2025-11-07"
      cert_valid_to       = "2026-11-07"

      country             = "US"
      state               = "Florida"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c3:3c:5e:2f:dc:57:0e:32:3b:8e:b3:78:9c:68:b0:16"
      )
}
