import "pe"

rule MAL_Compromised_Cert_ChromeLoader_ext_GlobalSign_13368B2B82123AEC8A55B305 {
   meta:
      description         = "Detects ChromeLoader_ext with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-13"
      version             = "1.0"

      hash                = "fdc12cbcde6e134a66612b63f4e4209d6217b6b8efd3151af47043c28ef9c95d"
      malware             = "ChromeLoader_ext"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Adzpalace LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "13:36:8b:2b:82:12:3a:ec:8a:55:b3:05"
      cert_thumbprint     = "764B4DC54A34D9A7A8BD72860D17198331CB2E02"
      cert_valid_from     = "2023-03-13"
      cert_valid_to       = "2024-03-13"

      country             = "GE"
      state               = "Imereti"
      locality            = "Samtredia"
      email               = "inquire@adzpalace.com"
      rdn_serial_number   = "438736487"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "13:36:8b:2b:82:12:3a:ec:8a:55:b3:05"
      )
}
