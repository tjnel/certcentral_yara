import "pe"

rule MAL_Compromised_Cert_TrueBot_Sectigo_00BE2F22C152BB218B898C4029056816A9 {
   meta:
      description         = "Detects TrueBot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-02-13"
      version             = "1.0"

      hash                = "c0f8aeeb2d11c6e751ee87c40ee609aceb1c1036706a5af0d3d78738b6cc4125"
      malware             = "TrueBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marts GmbH"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9"
      cert_thumbprint     = "85FE11E799609306516D82E026D4BAEF4C1E9AD3"
      cert_valid_from     = "2023-02-13"
      cert_valid_to       = "2024-02-13"

      country             = "AT"
      state               = "Steiermark"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9"
      )
}
