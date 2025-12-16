import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_70866B586685F4F39A5B4717 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-14"
      version             = "1.0"

      hash                = "53d60c9bff836ba832c39fecb2d57fffe594dfd0e9149b40f5c9e473bccbf34f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chengdu Nuoxin Times Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "70:86:6b:58:66:85:f4:f3:9a:5b:47:17"
      cert_thumbprint     = "ECA96BD74FB6B22848751E254B6DC9B8E2721F96"
      cert_valid_from     = "2024-05-14"
      cert_valid_to       = "2025-07-14"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "70:86:6b:58:66:85:f4:f3:9a:5b:47:17"
      )
}
