import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_26E509E714518BA6CD16D26C {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-08-28"
      version             = "1.0"

      hash                = "2818c4cbba444f3c288eb543b62a2f3f20fdd29b0df5f36cdf3ed14c4ffeda11"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhiya Yunke (Chengdu) Finance and Tax Service Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "26:e5:09:e7:14:51:8b:a6:cd:16:d2:6c"
      cert_thumbprint     = "49D0D851A7B74B2E76A3FC019AE527927444CC59"
      cert_valid_from     = "2023-08-28"
      cert_valid_to       = "2024-07-28"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "26:e5:09:e7:14:51:8b:a6:cd:16:d2:6c"
      )
}
