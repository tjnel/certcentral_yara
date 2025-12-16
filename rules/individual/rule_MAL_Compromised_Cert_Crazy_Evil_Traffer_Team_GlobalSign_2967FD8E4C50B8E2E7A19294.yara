import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_2967FD8E4C50B8E2E7A19294 {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-10"
      version             = "1.0"

      hash                = "6ec889fc18c8ae7a8531829afb593dc1f87539af9d67e38f3730c216c5a8746b"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "J-Golden Strive Trading Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "29:67:fd:8e:4c:50:b8:e2:e7:a1:92:94"
      cert_thumbprint     = "A3F8CCDF7EA080E45DA1596E035187B0BE47B4A9"
      cert_valid_from     = "2025-04-10"
      cert_valid_to       = "2026-04-11"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "???"
      rdn_serial_number   = "91510104MA69WBH41P"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "29:67:fd:8e:4c:50:b8:e2:e7:a1:92:94"
      )
}
