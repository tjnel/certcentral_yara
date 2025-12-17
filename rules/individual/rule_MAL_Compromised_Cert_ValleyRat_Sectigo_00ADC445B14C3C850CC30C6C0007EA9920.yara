import "pe"

rule MAL_Compromised_Cert_ValleyRat_Sectigo_00ADC445B14C3C850CC30C6C0007EA9920 {
   meta:
      description         = "Detects ValleyRat with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-27"
      version             = "1.0"

      hash                = "1a0fcd81af6b14b367f1ac93aa7a7b650450405f7652a17e667604e681d457b0"
      malware             = "ValleyRat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Acoustica, Inc"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA E36"
      cert_serial         = "00:ad:c4:45:b1:4c:3c:85:0c:c3:0c:6c:00:07:ea:99:20"
      cert_thumbprint     = "3F47F08CC583158F7F5B5CB22D1657CE2EBCB4CB"
      cert_valid_from     = "2025-04-27"
      cert_valid_to       = "2026-04-23"

      country             = "US"
      state               = "California"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA E36" and
         sig.serial == "00:ad:c4:45:b1:4c:3c:85:0c:c3:0c:6c:00:07:ea:99:20"
      )
}
