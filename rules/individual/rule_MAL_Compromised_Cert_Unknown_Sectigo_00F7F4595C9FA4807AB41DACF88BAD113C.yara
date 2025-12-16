import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00F7F4595C9FA4807AB41DACF88BAD113C {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-14"
      version             = "1.0"

      hash                = "62313b268ba0c0aa52c1e7e6822110af2b6df42761dc381dd45bbc6da487a1e2"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Plooto Star Inc"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:f7:f4:59:5c:9f:a4:80:7a:b4:1d:ac:f8:8b:ad:11:3c"
      cert_thumbprint     = "2347883329B8455D0A0F0D207A3A2279B339DFE8"
      cert_valid_from     = "2025-08-14"
      cert_valid_to       = "2026-08-14"

      country             = "US"
      state               = "Delaware"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "5767772"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:f7:f4:59:5c:9f:a4:80:7a:b4:1d:ac:f8:8b:ad:11:3c"
      )
}
