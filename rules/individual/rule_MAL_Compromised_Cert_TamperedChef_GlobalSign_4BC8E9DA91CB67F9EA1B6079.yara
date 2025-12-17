import "pe"

rule MAL_Compromised_Cert_TamperedChef_GlobalSign_4BC8E9DA91CB67F9EA1B6079 {
   meta:
      description         = "Detects TamperedChef with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-10"
      version             = "1.0"

      hash                = "e32d6b2b38b11db56ae5bce0d5e5413578a62960aa3fab48553f048c4d5f91f0"
      malware             = "TamperedChef"
      malware_type        = "Backdoor"
      malware_notes       = "This malware was distributed as a calendar application. The calendar contained special encoding to facilitate encoded communication. This malware was believed to be a continuation of the TamperedChef campaign which used hidden characters in recipes. See https://www.guidepointsecurity.com/blog/ai-exposes-homoglyph-hustle/ for more information"

      signer              = "CROWN SKY LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "4b:c8:e9:da:91:cb:67:f9:ea:1b:60:79"
      cert_thumbprint     = "154E1074C5850560AFD0F4F6F06993B1680CF034"
      cert_valid_from     = "2025-01-10"
      cert_valid_to       = "2026-01-11"

      country             = "UA"
      state               = "Kyiv"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "4b:c8:e9:da:91:cb:67:f9:ea:1b:60:79"
      )
}
