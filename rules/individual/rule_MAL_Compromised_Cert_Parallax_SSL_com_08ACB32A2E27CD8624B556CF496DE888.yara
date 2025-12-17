import "pe"

rule MAL_Compromised_Cert_Parallax_SSL_com_08ACB32A2E27CD8624B556CF496DE888 {
   meta:
      description         = "Detects Parallax with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-28"
      version             = "1.0"

      hash                = "bde8be565aa929b0c4ae5bb7fa6da74896779ec13bb28d488ade9445a5fe7137"
      malware             = "Parallax"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware is sold as a service. It started being seen first in 2019: https://www.morphisec.com/blog/parallax-rat-active-status/"

      signer              = "SPACE.WAW SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "08:ac:b3:2a:2e:27:cd:86:24:b5:56:cf:49:6d:e8:88"
      cert_thumbprint     = "C3D849F83D6C4FED05CED3C202F0174E82A34410"
      cert_valid_from     = "2025-08-28"
      cert_valid_to       = "2026-08-28"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "08:ac:b3:2a:2e:27:cd:86:24:b5:56:cf:49:6d:e8:88"
      )
}
