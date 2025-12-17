import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_54153343A319758492C3771B8717FBFB {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-01"
      version             = "1.0"

      hash                = "d22ef24a4e943d5fb36260ea2e46b046d2d6ce29f725e52167c00bfce0d94bdb"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Beyond Softwares And Consultancy Services Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "54:15:33:43:a3:19:75:84:92:c3:77:1b:87:17:fb:fb"
      cert_thumbprint     = "7E8865A242D35BAF812A5E39851B4497102CBF09"
      cert_valid_from     = "2024-05-01"
      cert_valid_to       = "2025-05-01"

      country             = "GB"
      state               = "England"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "54:15:33:43:a3:19:75:84:92:c3:77:1b:87:17:fb:fb"
      )
}
