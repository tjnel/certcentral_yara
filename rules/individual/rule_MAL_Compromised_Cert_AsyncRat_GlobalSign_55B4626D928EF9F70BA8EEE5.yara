import "pe"

rule MAL_Compromised_Cert_AsyncRat_GlobalSign_55B4626D928EF9F70BA8EEE5 {
   meta:
      description         = "Detects AsyncRat with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-24"
      version             = "1.0"

      hash                = "e0041d5fa7f5917fd0e88876ab063427f7161677e2162e633a6c2cf4ab3a126d"
      malware             = "AsyncRat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hoozoou Leeser Smart Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "55:b4:62:6d:92:8e:f9:f7:0b:a8:ee:e5"
      cert_thumbprint     = "A6834A954077ED77EA6815689D0AF84C78ED78BE"
      cert_valid_from     = "2024-04-24"
      cert_valid_to       = "2025-04-23"

      country             = "CN"
      state               = "Zhejiang"
      locality            = "Hangzhou"
      email               = "???"
      rdn_serial_number   = "91330108MA2B16Q83M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "55:b4:62:6d:92:8e:f9:f7:0b:a8:ee:e5"
      )
}
