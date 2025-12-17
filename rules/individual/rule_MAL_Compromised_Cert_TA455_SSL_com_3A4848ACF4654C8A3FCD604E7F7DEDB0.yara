import "pe"

rule MAL_Compromised_Cert_TA455_SSL_com_3A4848ACF4654C8A3FCD604E7F7DEDB0 {
   meta:
      description         = "Detects TA455 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-16"
      version             = "1.0"

      hash                = "d2db5b9b554470f5e9ad26f37b6b3f4f3dae336b3deea3f189933d007c17e3d8"
      malware             = "TA455"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sevenfeet Software AB"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "3a:48:48:ac:f4:65:4c:8a:3f:cd:60:4e:7f:7d:ed:b0"
      cert_thumbprint     = "D0DAAB3064E766CD74321FFF8D1714E94EB7AABD"
      cert_valid_from     = "2025-05-16"
      cert_valid_to       = "2026-05-16"

      country             = "SE"
      state               = "Stockholm"
      locality            = "Sundbyberg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "3a:48:48:ac:f4:65:4c:8a:3f:cd:60:4e:7f:7d:ed:b0"
      )
}
