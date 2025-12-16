import "pe"

rule MAL_Compromised_Cert_TA455_SSL_com_6FC5AE16744B71647A822C46313615E8 {
   meta:
      description         = "Detects TA455 with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "cf0c50670102e7fc6499e8d912ce1f5bd389fad5358d5cae53884593c337ac2e"
      malware             = "TA455"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Metriq Cloud Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6f:c5:ae:16:74:4b:71:64:7a:82:2c:46:31:36:15:e8"
      cert_thumbprint     = "E7DC7ADE3CD0AF5220E11871F5853C3C7F3E2482"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2026-03-14"

      country             = "PL"
      state               = "Silesian Voivodeship"
      locality            = "Katowice"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6f:c5:ae:16:74:4b:71:64:7a:82:2c:46:31:36:15:e8"
      )
}
