import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_65E6B4B9104AFCF9BEE6F984 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-11"
      version             = "1.0"

      hash                = "65a1d8ca5284d70df6a0a5cbd9a69c11c87e8cf7c17483aa213c31fe544c9c9f"
      malware             = "Unknown"
      malware_type        = "Remote access tool"
      malware_notes       = "Uses a python script to prepare a .NET binary to be compiled and executed: https://tria.ge/251129-pycsmsht2e/behavioral2"

      signer              = "WILD LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "65:e6:b4:b9:10:4a:fc:f9:be:e6:f9:84"
      cert_thumbprint     = "83FDE682DB8C8C8D039F21D2ECB5F6AC9FA38E4B"
      cert_valid_from     = "2025-03-11"
      cert_valid_to       = "2026-03-12"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700481423"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "65:e6:b4:b9:10:4a:fc:f9:be:e6:f9:84"
      )
}
