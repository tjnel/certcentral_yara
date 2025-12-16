import "pe"

rule MAL_Compromised_Cert_DeerStealer_GlobalSign_5C41DC105016B9996DA5276D {
   meta:
      description         = "Detects DeerStealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-08"
      version             = "1.0"

      hash                = "1bfda05df58c8323ce11b46db88f8d96b3355872785c285b0bb277afbde4baea"
      malware             = "DeerStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hefei Qiangwei Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:41:dc:10:50:16:b9:99:6d:a5:27:6d"
      cert_thumbprint     = "58829657EDD0D6DF7A82FB2898539FCE6BD79E75"
      cert_valid_from     = "2025-07-08"
      cert_valid_to       = "2026-07-09"

      country             = "CN"
      state               = "Anhui"
      locality            = "Hefei"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:41:dc:10:50:16:b9:99:6d:a5:27:6d"
      )
}
