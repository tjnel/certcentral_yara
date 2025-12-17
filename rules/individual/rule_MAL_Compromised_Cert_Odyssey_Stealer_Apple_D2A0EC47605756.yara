import "pe"

rule MAL_Compromised_Cert_Odyssey_Stealer_Apple_D2A0EC47605756 {
   meta:
      description         = "Detects Odyssey Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-30"
      version             = "1.0"

      hash                = "8bfdd239da6948b4903a92287cd6e15f86d96187c36ed75e796d99adcc09f66f"
      malware             = "Odyssey Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Amjadi Khalaily"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "d2:a0:ec:47:60:57:56"
      cert_thumbprint     = "EFF0E776FF8EFC64D969058F4253E2BDCFC0B1D5"
      cert_valid_from     = "2025-06-30"
      cert_valid_to       = "2027-02-01"

      country             = "-"
      state               = "-"
      locality            = "-"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "d2:a0:ec:47:60:57:56"
      )
}
