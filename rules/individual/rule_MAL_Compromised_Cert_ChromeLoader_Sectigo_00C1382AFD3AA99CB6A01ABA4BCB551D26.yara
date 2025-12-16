import "pe"

rule MAL_Compromised_Cert_ChromeLoader_Sectigo_00C1382AFD3AA99CB6A01ABA4BCB551D26 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-05-10"
      version             = "1.0"

      hash                = "97cce9d333dabe147055e39f98cec5c03342076e2b8aead63d3ffd0cd8d04702"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FH Manager"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:c1:38:2a:fd:3a:a9:9c:b6:a0:1a:ba:4b:cb:55:1d:26"
      cert_thumbprint     = "4E42EBA03C9C174C27B2408A5BCBEBE23CDD9BE4"
      cert_valid_from     = "2023-05-10"
      cert_valid_to       = "2025-05-09"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:c1:38:2a:fd:3a:a9:9c:b6:a0:1a:ba:4b:cb:55:1d:26"
      )
}
