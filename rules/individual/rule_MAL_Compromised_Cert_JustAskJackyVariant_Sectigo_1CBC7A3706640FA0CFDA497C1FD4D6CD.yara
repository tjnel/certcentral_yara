import "pe"

rule MAL_Compromised_Cert_JustAskJackyVariant_Sectigo_1CBC7A3706640FA0CFDA497C1FD4D6CD {
   meta:
      description         = "Detects JustAskJackyVariant with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "c10d362378d3f9c3f26389165730a30a1cc299b4e06460460d39ad5213713811"
      malware             = "JustAskJackyVariant"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Method Marketing Media LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "1c:bc:7a:37:06:64:0f:a0:cf:da:49:7c:1f:d4:d6:cd"
      cert_thumbprint     = "5B036DAD04DB22E8560716DEABC59A5E524B6BE2"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-25"

      country             = "US"
      state               = "Wyoming"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "1c:bc:7a:37:06:64:0f:a0:cf:da:49:7c:1f:d4:d6:cd"
      )
}
