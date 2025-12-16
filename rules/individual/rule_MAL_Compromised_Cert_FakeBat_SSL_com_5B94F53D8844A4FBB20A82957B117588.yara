import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_5B94F53D8844A4FBB20A82957B117588 {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-25"
      version             = "1.0"

      hash                = "12001dd924c265a33f33e33f29ed1bdc05aef8dbbabaa234b5695353649c8b4b"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Black Stone Softwares And Solutions Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "5b:94:f5:3d:88:44:a4:fb:b2:0a:82:95:7b:11:75:88"
      cert_thumbprint     = "23C2F06803C6B4301ADACFD87C99D898C0BB463F"
      cert_valid_from     = "2024-04-25"
      cert_valid_to       = "2025-04-25"

      country             = "GB"
      state               = "England"
      locality            = "Leicester"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "5b:94:f5:3d:88:44:a4:fb:b2:0a:82:95:7b:11:75:88"
      )
}
