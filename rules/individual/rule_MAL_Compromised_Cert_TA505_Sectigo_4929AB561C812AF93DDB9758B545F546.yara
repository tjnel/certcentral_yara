import "pe"

rule MAL_Compromised_Cert_TA505_Sectigo_4929AB561C812AF93DDB9758B545F546 {
   meta:
      description         = "Detects TA505 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-09"
      version             = "1.0"

      hash                = "026e25a18dae7bae363c4cba43b129164e0b2f21ada7b471a0c6a3238b7c1057"
      malware             = "TA505"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Everything Wow s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46"
      cert_thumbprint     = "C1E5574C891683C1FA811105049DCB67993F527E"
      cert_valid_from     = "2020-07-09"
      cert_valid_to       = "2021-07-09"

      country             = "CZ"
      state               = "Praha, Hlavní město"
      locality            = "Praha"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46"
      )
}
