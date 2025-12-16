import "pe"

rule MAL_Compromised_Cert_FakeDocusign_GlobalSign_5B7190D2FEB24B40EC00A1DE {
   meta:
      description         = "Detects FakeDocusign with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-22"
      version             = "1.0"

      hash                = "7c63a1520ce81dc43d2170ef1570b49627655d33e4987be2cccf8e99d9d4c99f"
      malware             = "FakeDocusign"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ACROATIC EDU-SOLUTIONS PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5b:71:90:d2:fe:b2:4b:40:ec:00:a1:de"
      cert_thumbprint     = "7935586577A2068FC2CF9CDD526DA9121093B8A6"
      cert_valid_from     = "2025-07-22"
      cert_valid_to       = "2026-07-23"

      country             = "IN"
      state               = "Bihar"
      locality            = "Muzaffarpur"
      email               = "bharat.acroaticsolutions@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5b:71:90:d2:fe:b2:4b:40:ec:00:a1:de"
      )
}
