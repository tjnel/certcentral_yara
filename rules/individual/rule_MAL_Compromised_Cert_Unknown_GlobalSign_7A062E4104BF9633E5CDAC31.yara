import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7A062E4104BF9633E5CDAC31 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-29"
      version             = "1.0"

      hash                = "8b5af508dcee04dbb7dabdffeff03726ef821182ffdb8a930af57e9e71740440"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zhengzhou 403 Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7a:06:2e:41:04:bf:96:33:e5:cd:ac:31"
      cert_thumbprint     = "D2BA5AE97458151B42E0C08B248F28EB918A93CF"
      cert_valid_from     = "2024-01-29"
      cert_valid_to       = "2025-01-29"

      country             = "CN"
      state               = "Henan"
      locality            = "Zhengzhou"
      email               = "???"
      rdn_serial_number   = "91410100MADAKY554Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7a:06:2e:41:04:bf:96:33:e5:cd:ac:31"
      )
}
