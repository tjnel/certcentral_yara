import "pe"

rule MAL_Compromised_Cert_Trojan_Banker_GlobalSign_6A7B1E613F855E13416DF15F {
   meta:
      description         = "Detects Trojan_Banker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-19"
      version             = "1.0"

      hash                = "b8086bb67c64728a5043f670920d37b6e37ae69d75f0dc50cd142aa99196a710"
      malware             = "Trojan_Banker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TNH99 VIET NAM JOINT STOCK COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6a:7b:1e:61:3f:85:5e:13:41:6d:f1:5f"
      cert_thumbprint     = "A2DCC193BFDF1E678F6E903C8B10311BCBA2997D"
      cert_valid_from     = "2024-08-19"
      cert_valid_to       = "2025-08-20"

      country             = "VN"
      state               = "Ha Noi"
      locality            = "Ha Noi"
      email               = "???"
      rdn_serial_number   = "0108300979"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6a:7b:1e:61:3f:85:5e:13:41:6d:f1:5f"
      )
}
