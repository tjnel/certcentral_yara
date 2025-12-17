import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_465DC834C3185EF4F0ECF74031134D21 {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "068e030b5144e2e3ec7d6531dc852a20396f9bea66bf0636ac9b9b8406c518a0"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Revington Creative Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "46:5d:c8:34:c3:18:5e:f4:f0:ec:f7:40:31:13:4d:21"
      cert_thumbprint     = "30ECFA55AFA1BE2A3F67B13F16BE98A9C8C86879"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "GB"
      state               = "England"
      locality            = "Folkestone"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "46:5d:c8:34:c3:18:5e:f4:f0:ec:f7:40:31:13:4d:21"
      )
}
