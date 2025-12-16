import "pe"

rule MAL_Compromised_Cert_Crazy_Evil_Traffer_Team_GlobalSign_18AC896DD6B2EA430E85F68E {
   meta:
      description         = "Detects Crazy Evil Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-20"
      version             = "1.0"

      hash                = "48a2c5750eb3d09f1c9b54becc1b261ce4bb659abecc38bd2bd56e5d20845c9d"
      malware             = "Crazy Evil Traffer Team"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "NEXTGENSOFTWARE COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "18:ac:89:6d:d6:b2:ea:43:0e:85:f6:8e"
      cert_thumbprint     = "B105B0EAEC1588C3157DC01245ED46182EEB9BD5"
      cert_valid_from     = "2025-02-20"
      cert_valid_to       = "2026-02-21"

      country             = "VN"
      state               = "Hồ Chí Minh"
      locality            = "Hồ Chí Minh"
      email               = "???"
      rdn_serial_number   = "0318797820"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "18:ac:89:6d:d6:b2:ea:43:0e:85:f6:8e"
      )
}
