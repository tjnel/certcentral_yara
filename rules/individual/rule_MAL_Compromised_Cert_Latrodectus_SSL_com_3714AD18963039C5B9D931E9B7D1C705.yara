import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_3714AD18963039C5B9D931E9B7D1C705 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-05"
      version             = "1.0"

      hash                = "2fe0bd27009fc17f5150257cf84a74429005f101744ca20a4ad599ed6e6869c1"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kerinthe Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "37:14:ad:18:96:30:39:c5:b9:d9:31:e9:b7:d1:c7:05"
      cert_thumbprint     = "EF1C0C7BE50F9FDA0666CEA043DB4818060A7478"
      cert_valid_from     = "2025-09-05"
      cert_valid_to       = "2026-09-05"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "37:14:ad:18:96:30:39:c5:b9:d9:31:e9:b7:d1:c7:05"
      )
}
