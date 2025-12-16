import "pe"

rule MAL_Compromised_Cert_FakeRVTools_GlobalSign_5A076B593C5E7DCA24430353 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-02"
      version             = "1.0"

      hash                = "75485847e431dddea1d9aee4cbc49066defc4fa8347cda67835009ca7d95b799"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "WEGUN (THAILAND) CO., LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:07:6b:59:3c:5e:7d:ca:24:43:03:53"
      cert_thumbprint     = "81162039094342A54A726E98C4DECB147152D193"
      cert_valid_from     = "2025-12-02"
      cert_valid_to       = "2026-11-21"

      country             = "TH"
      state               = "Chonburi"
      locality            = "Bang Lamung"
      email               = "???"
      rdn_serial_number   = "0205567025431"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:07:6b:59:3c:5e:7d:ca:24:43:03:53"
      )
}
