import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6A93DC8D2EA289E5B5965FECD0E4304D {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-11"
      version             = "1.0"

      hash                = "6fe37a5615b3c47e4c6f7eb7eca0bdcab9e05db9a39a1b6ec83917eed7bb72ba"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Công Ty Tnhh Thương Mại Và Dich Vụ La Media"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "6a:93:dc:8d:2e:a2:89:e5:b5:96:5f:ec:d0:e4:30:4d"
      cert_thumbprint     = "BC83BA97BBD2AD1B7BF363ED7B12E0AD69907EF4"
      cert_valid_from     = "2025-03-11"
      cert_valid_to       = "2026-03-11"

      country             = "VN"
      state               = "???"
      locality            = "Hà Nội"
      email               = "???"
      rdn_serial_number   = "0110305928"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "6a:93:dc:8d:2e:a2:89:e5:b5:96:5f:ec:d0:e4:30:4d"
      )
}
