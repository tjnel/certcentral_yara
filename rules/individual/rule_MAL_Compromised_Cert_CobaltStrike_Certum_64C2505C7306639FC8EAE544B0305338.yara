import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Certum_64C2505C7306639FC8EAE544B0305338 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-31"
      version             = "1.0"

      hash                = "7fa4ef5925f7374a93494b97a6ab43b0951c2d504972bbf43f9d29398e55481f"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "MANILA Solution as"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing CA SHA2"
      cert_serial         = "64:c2:50:5c:73:06:63:9f:c8:ea:e5:44:b0:30:53:38"
      cert_thumbprint     = "0443F1D09F590989BE0C6136C7E156945CFF0F47"
      cert_valid_from     = "2020-12-31"
      cert_valid_to       = "2021-12-31"

      country             = "CZ"
      state               = "Praha"
      locality            = "Praha"
      email               = "???"
      rdn_serial_number   = "05572959"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing CA SHA2" and
         sig.serial == "64:c2:50:5c:73:06:63:9f:c8:ea:e5:44:b0:30:53:38"
      )
}
