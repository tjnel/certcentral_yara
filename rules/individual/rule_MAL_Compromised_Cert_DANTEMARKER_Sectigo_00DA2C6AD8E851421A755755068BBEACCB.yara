import "pe"

rule MAL_Compromised_Cert_DANTEMARKER_Sectigo_00DA2C6AD8E851421A755755068BBEACCB {
   meta:
      description         = "Detects DANTEMARKER with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-20"
      version             = "1.0"

      hash                = "154c223efd649b929ee914902eb5a09ff3567b12422b359af4cc02ce97556481"
      malware             = "DANTEMARKER"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kamiesha Mason"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "00:da:2c:6a:d8:e8:51:42:1a:75:57:55:06:8b:be:ac:cb"
      cert_thumbprint     = "A1E6F174D6CC5F35ABE14E2A599F14BD0BF4D203"
      cert_valid_from     = "2024-05-20"
      cert_valid_to       = "2025-05-20"

      country             = "US"
      state               = "Texas"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "00:da:2c:6a:d8:e8:51:42:1a:75:57:55:06:8b:be:ac:cb"
      )
}
