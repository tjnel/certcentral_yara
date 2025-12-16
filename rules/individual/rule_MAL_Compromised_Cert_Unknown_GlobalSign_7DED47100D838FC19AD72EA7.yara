import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7DED47100D838FC19AD72EA7 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-10"
      version             = "1.0"

      hash                = "5460adc36bb1c60e66b55a584b11a2ad2a719a12718078afbf914e3dd07611c1"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Kaizhi Invest Management Limited Co."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7d:ed:47:10:0d:83:8f:c1:9a:d7:2e:a7"
      cert_thumbprint     = "3748C2A3629574A0A4C123693E26F849F54A6ADB"
      cert_valid_from     = "2025-03-10"
      cert_valid_to       = "2026-03-11"

      country             = "CN"
      state               = "Shanghai"
      locality            = "Shanghai"
      email               = "???"
      rdn_serial_number   = "9131011877712255X9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7d:ed:47:10:0d:83:8f:c1:9a:d7:2e:a7"
      )
}
