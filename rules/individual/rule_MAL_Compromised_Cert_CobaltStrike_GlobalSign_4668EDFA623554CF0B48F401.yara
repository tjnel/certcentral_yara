import "pe"

rule MAL_Compromised_Cert_CobaltStrike_GlobalSign_4668EDFA623554CF0B48F401 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-28"
      version             = "1.0"

      hash                = "ce38c96a69a8a1c6828e11742355c41b878198e08d7efbe73eefa1b5cbe623c5"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Zhengzhou 403 Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "46:68:ed:fa:62:35:54:cf:0b:48:f4:01"
      cert_thumbprint     = "B3BD6E706137ED999BFD6E51FE05FCA30C553C30"
      cert_valid_from     = "2025-03-28"
      cert_valid_to       = "2026-03-29"

      country             = "CN"
      state               = "Henan"
      locality            = "Zhengzhou"
      email               = "???"
      rdn_serial_number   = "91410100MADAKY554Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "46:68:ed:fa:62:35:54:cf:0b:48:f4:01"
      )
}
