import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_009B2D7164E12919C93E6261A52AB49EAE {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-14"
      version             = "1.0"

      hash                = "bcfd9c98c0a9c261f9bfcc85ccd12082f3debd460b666421b422f6639da39070"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Andres Martinez"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "00:9b:2d:71:64:e1:29:19:c9:3e:62:61:a5:2a:b4:9e:ae"
      cert_thumbprint     = "AE721B4F7130774504CE54A1948CD6BF29DFD53D"
      cert_valid_from     = "2024-02-14"
      cert_valid_to       = "2025-02-13"

      country             = "US"
      state               = "Texas"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "00:9b:2d:71:64:e1:29:19:c9:3e:62:61:a5:2a:b4:9e:ae"
      )
}
