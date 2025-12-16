import "pe"

rule MAL_Compromised_Cert_GoreloRMM_GlobalSign_7CEF117D5B3C634C182E1479 {
   meta:
      description         = "Detects GoreloRMM with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-12"
      version             = "1.0"

      hash                = "704772da03060dcc4e2b65817fa2d0baea31ae45984d2b3e0e32bea0a28552c5"
      malware             = "GoreloRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PrimeSnap Technologies Network Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:ef:11:7d:5b:3c:63:4c:18:2e:14:79"
      cert_thumbprint     = "9D600FDE1827AE6D6403B905EBAFE2C8633A610E"
      cert_valid_from     = "2024-11-12"
      cert_valid_to       = "2025-11-12"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:ef:11:7d:5b:3c:63:4c:18:2e:14:79"
      )
}
