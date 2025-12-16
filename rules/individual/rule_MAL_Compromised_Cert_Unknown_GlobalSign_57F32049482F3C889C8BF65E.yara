import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_57F32049482F3C889C8BF65E {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-05"
      version             = "1.0"

      hash                = "8f88ef7c7283a8114c3f06f8012cdfde9da9403a3a66ac9c690cf673e4f70732"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hebei Prolink Import & Export Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:f3:20:49:48:2f:3c:88:9c:8b:f6:5e"
      cert_thumbprint     = "906669A9289B957677FE42CDD5781DF6289C4869"
      cert_valid_from     = "2025-02-05"
      cert_valid_to       = "2026-02-06"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "911301027651889229"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:f3:20:49:48:2f:3c:88:9c:8b:f6:5e"
      )
}
