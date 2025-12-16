import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_3CCAA910608E55352E5340C47D01A9D8 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-14"
      version             = "1.0"

      hash                = "a236dd959abe6e818b494ebb9559d1e3909d828d32ebc7104bdb47a81982cfa2"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Domum - design s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3c:ca:a9:10:60:8e:55:35:2e:53:40:c4:7d:01:a9:d8"
      cert_thumbprint     = "78383AD96F00C6843126052D391DF597400925EA"
      cert_valid_from     = "2024-09-14"
      cert_valid_to       = "2025-09-14"

      country             = "CZ"
      state               = "Hlavní Mesto Praha"
      locality            = "Žižkov"
      email               = "???"
      rdn_serial_number   = "075 35 465"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3c:ca:a9:10:60:8e:55:35:2e:53:40:c4:7d:01:a9:d8"
      )
}
