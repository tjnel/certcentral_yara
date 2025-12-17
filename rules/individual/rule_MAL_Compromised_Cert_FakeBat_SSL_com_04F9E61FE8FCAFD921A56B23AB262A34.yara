import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_04F9E61FE8FCAFD921A56B23AB262A34 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-10-05"
      version             = "1.0"

      hash                = "e9aab10f7244a4efdc8946ae994a1155f21412590ba30b5abc9e5a9a69a8542e"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Alto Verde Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "04:f9:e6:1f:e8:fc:af:d9:21:a5:6b:23:ab:26:2a:34"
      cert_thumbprint     = "7A67E5E2027644FA1F74D40711A124B752FA66A6"
      cert_valid_from     = "2023-10-05"
      cert_valid_to       = "2024-10-04"

      country             = "GB"
      state               = "???"
      locality            = "Leicester"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "04:f9:e6:1f:e8:fc:af:d9:21:a5:6b:23:ab:26:2a:34"
      )
}
