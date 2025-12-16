import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00B1566A28378C598B0FAB2E42EC359F01 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-15"
      version             = "1.0"

      hash                = "a946a59d49e946a1eebfcf6ff2e8e46515380cd4668f60b265cb1a891ee0bd68"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Internet Share Media LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b1:56:6a:28:37:8c:59:8b:0f:ab:2e:42:ec:35:9f:01"
      cert_thumbprint     = "1E2DD38E14B98BB003C2BE96A7414FE747C7CCCE"
      cert_valid_from     = "2024-05-15"
      cert_valid_to       = "2025-05-15"

      country             = "US"
      state               = "Delaware"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "7634313"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b1:56:6a:28:37:8c:59:8b:0f:ab:2e:42:ec:35:9f:01"
      )
}
