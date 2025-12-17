import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_47EC895C33BBE4A80A3EB1BCBBF6128B {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-18"
      version             = "1.0"

      hash                = "d4c9ee556fda527e59a0431bfa7f4324318ca384001fa0856635c39bae337431"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Emk Consulting Engineers Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "47:ec:89:5c:33:bb:e4:a8:0a:3e:b1:bc:bb:f6:12:8b"
      cert_thumbprint     = "C78EC5CF3C77D1432911A72D9CD017139BF4BA47"
      cert_valid_from     = "2024-05-18"
      cert_valid_to       = "2025-05-18"

      country             = "GB"
      state               = "Northern Ireland"
      locality            = "Londonderry"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "47:ec:89:5c:33:bb:e4:a8:0a:3e:b1:bc:bb:f6:12:8b"
      )
}
