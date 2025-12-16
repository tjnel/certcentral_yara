import "pe"

rule MAL_Compromised_Cert_BazaLoader_DigiCert_0BAB6A2AA84B495D9E554A4C42C0126D {
   meta:
      description         = "Detects BazaLoader with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-21"
      version             = "1.0"

      hash                = "cae79d8ceb527eb8367b1df9e916718e4329d2768ed0b7e61f7c406af9d21f31"
      malware             = "BazaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NOSOV SP Z O O"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d"
      cert_thumbprint     = "230614366DDAC05C9120A852058C24FA89972535"
      cert_valid_from     = "2020-08-21"
      cert_valid_to       = "2021-08-18"

      country             = "PL"
      state               = "???"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000730830"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d"
      )
}
