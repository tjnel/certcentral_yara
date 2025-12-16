import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_6D855F60232A59021258A63D {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-27"
      version             = "1.0"

      hash                = "8bb49036e0354865d888ee92532b5fa467667b71a2522bc2ea9bf8476be4a088"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "Huethem Silicon Electronic Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6d:85:5f:60:23:2a:59:02:12:58:a6:3d"
      cert_thumbprint     = "800B68CDE8472937AA79EC95F98FF2865847C8EA"
      cert_valid_from     = "2025-02-27"
      cert_valid_to       = "2026-02-28"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5FD6WK46"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6d:85:5f:60:23:2a:59:02:12:58:a6:3d"
      )
}
