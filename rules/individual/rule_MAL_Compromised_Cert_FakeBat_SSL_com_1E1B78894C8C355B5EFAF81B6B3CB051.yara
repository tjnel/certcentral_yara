import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_1E1B78894C8C355B5EFAF81B6B3CB051 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-17"
      version             = "1.0"

      hash                = "a2768e6bb920bc9224662c08c7da7d0c09fb2101662a8265a20a27b90140122d"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Futurewest Creative Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "1e:1b:78:89:4c:8c:35:5b:5e:fa:f8:1b:6b:3c:b0:51"
      cert_thumbprint     = "91332F61C65CE008BA9E992003310C0DE175DA15"
      cert_valid_from     = "2024-06-17"
      cert_valid_to       = "2025-06-17"

      country             = "GB"
      state               = "London Borough of Hounslow"
      locality            = "Chiswick"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "1e:1b:78:89:4c:8c:35:5b:5e:fa:f8:1b:6b:3c:b0:51"
      )
}
