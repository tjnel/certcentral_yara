import "pe"

rule MAL_Compromised_Cert_Odyssey_Stealer_Apple_2BEB4AB91970859A {
   meta:
      description         = "Detects Odyssey Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "c916f3710ba7f5d8413460e0c2336cb043312cc253247a5a03926a816db58b1e"
      malware             = "Odyssey Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Augustin Brunelle"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "2b:eb:4a:b9:19:70:85:9a"
      cert_thumbprint     = "F755D1D68D42294B2DD3DB8C14A14CE388D4BA57"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "2b:eb:4a:b9:19:70:85:9a"
      )
}
