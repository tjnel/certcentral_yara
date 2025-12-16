import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_1E074DA361479DD29F2E014AB6ACF5F2 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-15"
      version             = "1.0"

      hash                = "934f86cd47c0deb85fc6f6e382f55c591805d7056075f215a291a24388730ec1"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cockos Incorporated"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "1e:07:4d:a3:61:47:9d:d2:9f:2e:01:4a:b6:ac:f5:f2"
      cert_thumbprint     = "EA7B7AC4E637D8FBDDFE5D2FB691F1A0C10E3C43"
      cert_valid_from     = "2025-04-15"
      cert_valid_to       = "2025-12-18"

      country             = "US"
      state               = "New York"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "1e:07:4d:a3:61:47:9d:d2:9f:2e:01:4a:b6:ac:f5:f2"
      )
}
