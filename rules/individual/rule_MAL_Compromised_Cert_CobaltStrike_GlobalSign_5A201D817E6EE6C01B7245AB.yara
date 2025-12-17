import "pe"

rule MAL_Compromised_Cert_CobaltStrike_GlobalSign_5A201D817E6EE6C01B7245AB {
   meta:
      description         = "Detects CobaltStrike with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-24"
      version             = "1.0"

      hash                = "c7c33d102ee200c14c251078310316104418e743df16c2310c9afac47e313908"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "安徽哲凯网络科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:20:1d:81:7e:6e:e6:c0:1b:72:45:ab"
      cert_thumbprint     = "0C6EFEE2B93507E766F12B25101E90097517D3C6"
      cert_valid_from     = "2024-06-24"
      cert_valid_to       = "2025-06-25"

      country             = "CN"
      state               = "安徽"
      locality            = "合肥"
      email               = "???"
      rdn_serial_number   = "91340104MA2UHG725W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:20:1d:81:7e:6e:e6:c0:1b:72:45:ab"
      )
}
