import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_3C7F0B3E22B1572B71883C94 {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-06"
      version             = "1.0"

      hash                = "681c59113d3a87a0086716b91642258097dc4da809d76c5566d184783d3b6cd4"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "Shanxi Jiusheng Tongtai Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3c:7f:0b:3e:22:b1:57:2b:71:88:3c:94"
      cert_thumbprint     = "B4335AA9A34670C139BAD65C3DF83CAAA5147BB1"
      cert_valid_from     = "2025-05-06"
      cert_valid_to       = "2026-05-07"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Jinzhong"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3c:7f:0b:3e:22:b1:57:2b:71:88:3c:94"
      )
}
