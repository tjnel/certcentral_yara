import "pe"

rule MAL_Compromised_Cert_FakeBat_SSL_com_2BBB9B7FE942FB6EA60F86D578A64EAD {
   meta:
      description         = "Detects FakeBat with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-12"
      version             = "1.0"

      hash                = "647012c5141844a860ba474ef3b239a845170e8c4f5631e8cbdc7781dfe468a2"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "Dinomike Design Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2b:bb:9b:7f:e9:42:fb:6e:a6:0f:86:d5:78:a6:4e:ad"
      cert_thumbprint     = "3DEFCB7054AD6C39664013ACE33DAF675DEEB9AB"
      cert_valid_from     = "2024-05-12"
      cert_valid_to       = "2025-05-12"

      country             = "GB"
      state               = "???"
      locality            = "Kettering"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2b:bb:9b:7f:e9:42:fb:6e:a6:0f:86:d5:78:a6:4e:ad"
      )
}
