import "pe"

rule MAL_Compromised_Cert_ConvertMate_FakeFileConverter_GlobalSign_77632688BC1B58D31BC7DF0D {
   meta:
      description         = "Detects ConvertMate, FakeFileConverter with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-14"
      version             = "1.0"

      hash                = "09c2af472ab86b62a702e94a39df2bef09205f4249ed871cbeece751c1e7ef4f"
      malware             = "ConvertMate, FakeFileConverter"
      malware_type        = "Backdoor"
      malware_notes       = "Malware creates a scheduled task to check in with C2 daily. Can receive and decrypt AES encoded payloads received by the C2. See  https://blog.lukeacha.com/2025/11/suspicious-converter-obfuscated-strings.html for more details."

      signer              = "AMARYLLIS SIGNAL LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "77:63:26:88:bc:1b:58:d3:1b:c7:df:0d"
      cert_thumbprint     = "02C4B0C7438F3AE718FFA47137B75151713F38EA"
      cert_valid_from     = "2025-01-14"
      cert_valid_to       = "2026-01-15"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Tel Aviv"
      email               = "support@amarylisignal.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "77:63:26:88:bc:1b:58:d3:1b:c7:df:0d"
      )
}
