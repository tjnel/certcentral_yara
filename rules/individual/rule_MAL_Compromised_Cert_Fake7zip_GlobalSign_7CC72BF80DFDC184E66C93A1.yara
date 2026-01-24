import "pe"

rule MAL_Compromised_Cert_Fake7zip_GlobalSign_7CC72BF80DFDC184E66C93A1 {
   meta:
      description         = "Detects Fake7zip with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-18"
      version             = "1.0"

      hash                = "408a89bc9966e76f3a192ecbf47b36fdc8ddaa4067aaee753c0bd6ae502f5cea"
      malware             = "Fake7zip"
      malware_type        = "Unknown"
      malware_notes       = "Fake 7zip installer from unofficial site. Ref: https://wizsafe.iij.ad.jp/2026/01/2075/"

      signer              = "JOZEAL NETWORK TECHNOLOGY CO., LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7c:c7:2b:f8:0d:fd:c1:84:e6:6c:93:a1"
      cert_thumbprint     = "EBC8B1DE7ADAF53A0E9E1E1553D5018C014C5B64"
      cert_valid_from     = "2023-04-18"
      cert_valid_to       = "2026-04-18"

      country             = "HK"
      state               = "Kowloon"
      locality            = "Kwun Tong"
      email               = "???"
      rdn_serial_number   = "2940285"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7c:c7:2b:f8:0d:fd:c1:84:e6:6c:93:a1"
      )
}
