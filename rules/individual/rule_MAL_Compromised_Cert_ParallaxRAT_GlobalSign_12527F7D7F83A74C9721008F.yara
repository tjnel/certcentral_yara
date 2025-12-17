import "pe"

rule MAL_Compromised_Cert_ParallaxRAT_GlobalSign_12527F7D7F83A74C9721008F {
   meta:
      description         = "Detects ParallaxRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-04"
      version             = "1.0"

      hash                = "f95f203c80586c9e6ea078bc983f690e8b15c6e133e70554fb75b3469e3dae17"
      malware             = "ParallaxRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "Blockfi Ruinor Security Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "12:52:7f:7d:7f:83:a7:4c:97:21:00:8f"
      cert_thumbprint     = "091A22C7A90C723EA2F1A9D38374D3F7BF855371"
      cert_valid_from     = "2024-06-04"
      cert_valid_to       = "2025-06-05"

      country             = "CN"
      state               = "Shandong"
      locality            = "Jinan"
      email               = "???"
      rdn_serial_number   = "91370102307284861T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "12:52:7f:7d:7f:83:a7:4c:97:21:00:8f"
      )
}
