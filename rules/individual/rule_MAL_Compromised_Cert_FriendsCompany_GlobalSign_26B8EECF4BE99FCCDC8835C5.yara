import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_26B8EECF4BE99FCCDC8835C5 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-10"
      version             = "1.0"

      hash                = "2c8cf7233fd4c75bfb19cbf6b573607e6cdf684cb010288e49bcbda6941202a8"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "SHEEN & PROSPECTS INFOTECH PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "26:b8:ee:cf:4b:e9:9f:cc:dc:88:35:c5"
      cert_thumbprint     = "C2ADF7CD38EB1446B210E97FEF3F89D95C9F7E84"
      cert_valid_from     = "2025-06-10"
      cert_valid_to       = "2026-06-11"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "sheenandprospectsinfotech@gmail.com"
      rdn_serial_number   = "U74999BR2016PTC032005"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "26:b8:ee:cf:4b:e9:9f:cc:dc:88:35:c5"
      )
}
