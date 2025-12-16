import "pe"

rule MAL_Compromised_Cert_FakeBat_Certificate_SSL_com_7DBC9D5DE3181ADE787B91C1F6E57E48 {
   meta:
      description         = "Detects FakeBat_Certificate with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-17"
      version             = "1.0"

      hash                = "89756b6cff919b03e88c1251a46d132723a79866227785a835d7e67ad4123032"
      malware             = "FakeBat_Certificate"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Cloudava Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "7d:bc:9d:5d:e3:18:1a:de:78:7b:91:c1:f6:e5:7e:48"
      cert_thumbprint     = "3DF175D0E8E90DA439BA0D6B790FF41C787AEAFC"
      cert_valid_from     = "2024-05-17"
      cert_valid_to       = "2025-05-17"

      country             = "GB"
      state               = "Middlesex"
      locality            = "Harrow On The Hill"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "7d:bc:9d:5d:e3:18:1a:de:78:7b:91:c1:f6:e5:7e:48"
      )
}
