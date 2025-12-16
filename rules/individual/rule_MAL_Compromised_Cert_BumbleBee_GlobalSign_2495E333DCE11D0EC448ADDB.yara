import "pe"

rule MAL_Compromised_Cert_BumbleBee_GlobalSign_2495E333DCE11D0EC448ADDB {
   meta:
      description         = "Detects BumbleBee with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-29"
      version             = "1.0"

      hash                = "a67bae3dd73789e892b5114a157d992424d367aae11c5fbaa80be639d6dec798"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dongguan Shunkaitong Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "24:95:e3:33:dc:e1:1d:0e:c4:48:ad:db"
      cert_thumbprint     = "42C99C73B698BAB9CCC531D65FB6542557AC66E0"
      cert_valid_from     = "2025-04-29"
      cert_valid_to       = "2026-04-30"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Dongguan"
      email               = "???"
      rdn_serial_number   = "91441900MA57EGAN4R"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "24:95:e3:33:dc:e1:1d:0e:c4:48:ad:db"
      )
}
