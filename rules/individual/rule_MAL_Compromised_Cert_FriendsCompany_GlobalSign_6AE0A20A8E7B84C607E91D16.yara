import "pe"

rule MAL_Compromised_Cert_FriendsCompany_GlobalSign_6AE0A20A8E7B84C607E91D16 {
   meta:
      description         = "Detects FriendsCompany with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-10"
      version             = "1.0"

      hash                = "b557531bcb94bb8208d688c9f791f9aa265de97ce7c8e74f7a72a9313069dd47"
      malware             = "FriendsCompany"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "DJ Webb Investments LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6a:e0:a2:0a:8e:7b:84:c6:07:e9:1d:16"
      cert_thumbprint     = "7E5D13F73C5F23B8996CAD0EBEAFFC248C9FDE74"
      cert_valid_from     = "2025-02-10"
      cert_valid_to       = "2026-02-11"

      country             = "US"
      state               = "Alaska"
      locality            = "Anchorage"
      email               = "???"
      rdn_serial_number   = "10155897"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6a:e0:a2:0a:8e:7b:84:c6:07:e9:1d:16"
      )
}
