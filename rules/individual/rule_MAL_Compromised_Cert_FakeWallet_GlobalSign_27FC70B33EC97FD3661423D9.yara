import "pe"

rule MAL_Compromised_Cert_FakeWallet_GlobalSign_27FC70B33EC97FD3661423D9 {
   meta:
      description         = "Detects FakeWallet with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-07"
      version             = "1.0"

      hash                = "12b178ea9534a3a36a4fbd7646995eec715a6566ab2cc20dfe37996435d6d09d"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RICHFUN MINERAL COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "27:fc:70:b3:3e:c9:7f:d3:66:14:23:d9"
      cert_thumbprint     = "6808BDB984164944F5D63966A9429EA89655098C"
      cert_valid_from     = "2025-05-07"
      cert_valid_to       = "2026-05-08"

      country             = "VN"
      state               = "Hà Nam"
      locality            = "Hà Nam"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "27:fc:70:b3:3e:c9:7f:d3:66:14:23:d9"
      )
}
