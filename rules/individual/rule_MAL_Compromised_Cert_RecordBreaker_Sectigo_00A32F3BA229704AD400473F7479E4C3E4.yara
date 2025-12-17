import "pe"

rule MAL_Compromised_Cert_RecordBreaker_Sectigo_00A32F3BA229704AD400473F7479E4C3E4 {
   meta:
      description         = "Detects RecordBreaker with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-21"
      version             = "1.0"

      hash                = "002500484b7931b442a89842c37f22d3fa4038e8d4a803ccd6c5c9651523a294"
      malware             = "RecordBreaker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOTUL SOLUTIONS LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:a3:2f:3b:a2:29:70:4a:d4:00:47:3f:74:79:e4:c3:e4"
      cert_thumbprint     = "898B9EA9638B86A5FF87EDC5731C17F529F17A4D"
      cert_valid_from     = "2023-03-21"
      cert_valid_to       = "2024-03-20"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:a3:2f:3b:a2:29:70:4a:d4:00:47:3f:74:79:e4:c3:e4"
      )
}
