import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_7CE6D17250E006C15A67A0D108B63DA2 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-11"
      version             = "1.0"

      hash                = "fc1060dbded7cacfa2edd46b7c894c4e6757f5a28f096e64392aac85ebbcf8d0"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Datamanage Software Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "7c:e6:d1:72:50:e0:06:c1:5a:67:a0:d1:08:b6:3d:a2"
      cert_thumbprint     = "893C93A879EE8B4F75C01255AC95EADFA17079DB"
      cert_valid_from     = "2024-07-11"
      cert_valid_to       = "2025-07-11"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "7c:e6:d1:72:50:e0:06:c1:5a:67:a0:d1:08:b6:3d:a2"
      )
}
