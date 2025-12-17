import "pe"

rule MAL_Compromised_Cert_Castleloader_GlobalSign_601EAD2413898A3EDBFE37D6 {
   meta:
      description         = "Detects Castleloader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-02"
      version             = "1.0"

      hash                = "2a040d0bb9f335c12e7dd809d66b328e9114445eccfc79f5d797cc9636b6c72d"
      malware             = "Castleloader"
      malware_type        = "Initial access tool"
      malware_notes       = "This is an initial access tool that is frequenty used to load infostealers or remote access tools, sold as Malware-as-a-Service: https://www.ibm.com/think/x-force/dissecting-castlebot-maas-operation"

      signer              = "LLC KHD GROUP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "60:1e:ad:24:13:89:8a:3e:db:fe:37:d6"
      cert_thumbprint     = "8E5AAAF4DC669CD201DD9252E5A6465721DF816D"
      cert_valid_from     = "2025-06-02"
      cert_valid_to       = "2026-06-03"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "60:1e:ad:24:13:89:8a:3e:db:fe:37:d6"
      )
}
