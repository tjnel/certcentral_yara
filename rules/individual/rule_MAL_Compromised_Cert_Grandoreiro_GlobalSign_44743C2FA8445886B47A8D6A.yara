import "pe"

rule MAL_Compromised_Cert_Grandoreiro_GlobalSign_44743C2FA8445886B47A8D6A {
   meta:
      description         = "Detects Grandoreiro with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-13"
      version             = "1.0"

      hash                = "ed7b784eac6d49f7978cc30183a053d3224bc90a53708351c184dedf17dd25b2"
      malware             = "Grandoreiro"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MR Software GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "44:74:3c:2f:a8:44:58:86:b4:7a:8d:6a"
      cert_thumbprint     = "DA0253D911E76828A744E2F712BA7F20C6DE4511"
      cert_valid_from     = "2024-05-13"
      cert_valid_to       = "2025-05-14"

      country             = "AT"
      state               = "Steiermark"
      locality            = "Kalsdorf bei Graz"
      email               = "admin@mrsoftwareltd.com"
      rdn_serial_number   = "616318a"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "44:74:3c:2f:a8:44:58:86:b4:7a:8d:6a"
      )
}
