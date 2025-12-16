import "pe"

rule MAL_Compromised_Cert_FakeChromeExtension_GlobalSign_627C9A310E788378C67B53FA {
   meta:
      description         = "Detects FakeChromeExtension with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-08"
      version             = "1.0"

      hash                = "a46036073cb4634c35b928aac84e1b82abc59e7d5f92f552c42ae8217e16508d"
      malware             = "FakeChromeExtension"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC A G M"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "62:7c:9a:31:0e:78:83:78:c6:7b:53:fa"
      cert_thumbprint     = "1F789E01043C7D50986581FE769B0EA8EC95CA53"
      cert_valid_from     = "2025-07-08"
      cert_valid_to       = "2026-07-09"

      country             = "RU"
      state               = "Astrakhan Oblast"
      locality            = "Astrakhan"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "62:7c:9a:31:0e:78:83:78:c6:7b:53:fa"
      )
}
