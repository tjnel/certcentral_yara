import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_5499FE809B614A77BA2436132C56B91F {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-11"
      version             = "1.0"

      hash                = "356299531dd96ee5a3567a8a303f0104979f355bbabb50c0cddc6aa18f564b07"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Clachan Design Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "54:99:fe:80:9b:61:4a:77:ba:24:36:13:2c:56:b9:1f"
      cert_thumbprint     = "7D5E2E3C2D29FC941438187AC34567FE1210968A"
      cert_valid_from     = "2024-05-11"
      cert_valid_to       = "2025-05-11"

      country             = "GB"
      state               = "London Borough of Merton"
      locality            = "New Malden"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "54:99:fe:80:9b:61:4a:77:ba:24:36:13:2c:56:b9:1f"
      )
}
