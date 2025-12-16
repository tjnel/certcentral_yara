import "pe"

rule MAL_Compromised_Cert_asyncrat_GlobalSign_310E2734DDD4AA4754E205F4 {
   meta:
      description         = "Detects asyncrat with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-18"
      version             = "1.0"

      hash                = "f286629a9391e4bd928c9c07e604d452062a45e077a48c550f95dc00549369a5"
      malware             = "asyncrat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jerloosr Kliokery Innovation Institute Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "31:0e:27:34:dd:d4:aa:47:54:e2:05:f4"
      cert_thumbprint     = "13B0F07E1F60124E1C55E8488DDCDCE4BF7E378E"
      cert_valid_from     = "2025-03-18"
      cert_valid_to       = "2026-03-19"

      country             = "CN"
      state               = "Shandong"
      locality            = "Tai'an"
      email               = "???"
      rdn_serial_number   = "91370900MA3N89RR4L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "31:0e:27:34:dd:d4:aa:47:54:e2:05:f4"
      )
}
