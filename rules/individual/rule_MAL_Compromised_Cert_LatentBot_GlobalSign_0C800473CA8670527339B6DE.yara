import "pe"

rule MAL_Compromised_Cert_LatentBot_GlobalSign_0C800473CA8670527339B6DE {
   meta:
      description         = "Detects LatentBot with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-26"
      version             = "1.0"

      hash                = "4f964a67f2487c39f0f7a69468ae00f8a2d8b04d5c17904e2f40aa99602ca2ae"
      malware             = "LatentBot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ChasingFire Dream Technologies Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "0c:80:04:73:ca:86:70:52:73:39:b6:de"
      cert_thumbprint     = "8733550C4D5DEB2F055420E049353B93F724D5F7"
      cert_valid_from     = "2024-09-26"
      cert_valid_to       = "2025-09-27"

      country             = "CN"
      state               = "Hubei"
      locality            = "Wuhan"
      email               = "???"
      rdn_serial_number   = "91420115MA4L020L06"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "0c:80:04:73:ca:86:70:52:73:39:b6:de"
      )
}
