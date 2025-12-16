import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_7DD8BDEDD9E79593FBE0C25B114670A6 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-31"
      version             = "1.0"

      hash                = "6846d9bac1b70152637998118523c5baa97f124c81036e9865d6a3b80cd031ee"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hatem Sakr"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "7d:d8:bd:ed:d9:e7:95:93:fb:e0:c2:5b:11:46:70:a6"
      cert_thumbprint     = "112D38DDFCF0FCE6C2C352598F821E1F2A7F76AC"
      cert_valid_from     = "2024-12-31"
      cert_valid_to       = "2025-12-31"

      country             = "EG"
      state               = "???"
      locality            = "Banha"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "7d:d8:bd:ed:d9:e7:95:93:fb:e0:c2:5b:11:46:70:a6"
      )
}
