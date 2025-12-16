import "pe"

rule MAL_Compromised_Cert_ChromeLoader_ext_GlobalSign_33E2A5E1E0F425C3E0D76F9D {
   meta:
      description         = "Detects ChromeLoader_ext with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-14"
      version             = "1.0"

      hash                = "85781c1fdb2d0a16d540f8b2c2bb776d37de2bdf61db9160546799806876fc0d"
      malware             = "ChromeLoader_ext"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Monetize forward LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "33:e2:a5:e1:e0:f4:25:c3:e0:d7:6f:9d"
      cert_thumbprint     = "0C90F97DF6C8DA66C1BAB938B4B7A033505A689F"
      cert_valid_from     = "2023-04-14"
      cert_valid_to       = "2024-04-14"

      country             = "GE"
      state               = "Imereti"
      locality            = "Samtredia"
      email               = "Information@monetizeforward.com"
      rdn_serial_number   = "438736539"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "33:e2:a5:e1:e0:f4:25:c3:e0:d7:6f:9d"
      )
}
