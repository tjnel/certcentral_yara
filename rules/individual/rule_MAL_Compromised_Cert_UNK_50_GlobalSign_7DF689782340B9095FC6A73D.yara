import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_7DF689782340B9095FC6A73D {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-11"
      version             = "1.0"

      hash                = "517b5e0180f10c4fd3e546834a0309cebba804cc0f7273aab7cbd66b20ee2d63"
      malware             = "UNK-50"
      malware_type        = "Infostealer"
      malware_notes       = "This malware is often pushed via social media advertising fake AI applications and fake NSFW applications: https://x.com/g0njxa/status/1959989875404366284?s=20"

      signer              = "Service LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7d:f6:89:78:23:40:b9:09:5f:c6:a7:3d"
      cert_thumbprint     = "5392FAFF652E01DF1551AE5B7A82423F0F7341BE"
      cert_valid_from     = "2025-06-11"
      cert_valid_to       = "2026-06-12"

      country             = "RU"
      state               = "Saint Petersburg"
      locality            = "Saint Petersburg"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7d:f6:89:78:23:40:b9:09:5f:c6:a7:3d"
      )
}
