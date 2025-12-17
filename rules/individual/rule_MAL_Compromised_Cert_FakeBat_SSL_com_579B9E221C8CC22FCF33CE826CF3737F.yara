import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_579B9E221C8CC22FCF33CE826CF3737F {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-09"
      version             = "1.0"

      hash                = "5660d461a24e9a15ecb60891bd725a464f8d9a5d20d07852838604f58ba8ff77"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Lencall Technical Services Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "57:9b:9e:22:1c:8c:c2:2f:cf:33:ce:82:6c:f3:73:7f"
      cert_thumbprint     = "0ECBC9F0E2714A5520621C33781A7EC65805B669"
      cert_valid_from     = "2024-05-09"
      cert_valid_to       = "2025-05-09"

      country             = "GB"
      state               = "Scotland"
      locality            = "Nairn"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "57:9b:9e:22:1c:8c:c2:2f:cf:33:ce:82:6c:f3:73:7f"
      )
}
