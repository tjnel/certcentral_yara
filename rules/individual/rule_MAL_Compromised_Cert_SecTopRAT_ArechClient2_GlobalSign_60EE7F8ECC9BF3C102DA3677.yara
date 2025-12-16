import "pe"

rule MAL_Compromised_Cert_SecTopRAT_ArechClient2_GlobalSign_60EE7F8ECC9BF3C102DA3677 {
   meta:
      description         = "Detects SecTopRAT,ArechClient2 with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-01"
      version             = "1.0"

      hash                = "645e557e03904aca48c1e0467a94de924a8359b6e5a98354a6e44aa2abeba84a"
      malware             = "SecTopRAT,ArechClient2"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "LLC Yusal"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:ee:7f:8e:cc:9b:f3:c1:02:da:36:77"
      cert_thumbprint     = "D7DEC238BE024974778DAA4070394B21A9D40D83"
      cert_valid_from     = "2025-02-01"
      cert_valid_to       = "2026-01-30"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1196313074726"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:ee:7f:8e:cc:9b:f3:c1:02:da:36:77"
      )
}
