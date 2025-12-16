import "pe"

rule MAL_Compromised_Cert_WikiLoader_GlobalSign_2DDFCE3F64D9D03113A1EC75 {
   meta:
      description         = "Detects WikiLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-26"
      version             = "1.0"

      hash                = "21689eafdfd6005ae75683a423b7816592cdf9aae03d983782d9272bb71787b9"
      malware             = "WikiLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Canton Pure Jonna Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2d:df:ce:3f:64:d9:d0:31:13:a1:ec:75"
      cert_thumbprint     = "3E6B9866607BBB91020938BF77CD7A8E919692B0"
      cert_valid_from     = "2024-08-26"
      cert_valid_to       = "2025-08-27"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440114MACL0TN54Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2d:df:ce:3f:64:d9:d0:31:13:a1:ec:75"
      )
}
