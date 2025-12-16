import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_085983378E4F015ACCF56A49 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-03"
      version             = "1.0"

      hash                = "518d779f9ebed493a6dde8c0e90098b888976b6785809a30e60ddf106b0289c8"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "VALEMO GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "08:59:83:37:8e:4f:01:5a:cc:f5:6a:49"
      cert_thumbprint     = "209B0B67CE472D957E0CBFA51D3B6B131E22FBD5"
      cert_valid_from     = "2025-02-03"
      cert_valid_to       = "2026-02-04"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "admin@valemogmbh.com"
      rdn_serial_number   = "633901h"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "08:59:83:37:8e:4f:01:5a:cc:f5:6a:49"
      )
}
