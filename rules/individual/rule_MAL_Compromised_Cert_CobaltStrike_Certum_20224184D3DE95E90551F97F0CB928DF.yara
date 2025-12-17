import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Certum_20224184D3DE95E90551F97F0CB928DF {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-20"
      version             = "1.0"

      hash                = "9f0951b5bc28dcedf979692f1a2bde41d848c6dbb17d7f9482f188cdde727aa4"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Keroro Software LLC"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "20:22:41:84:d3:de:95:e9:05:51:f9:7f:0c:b9:28:df"
      cert_thumbprint     = "87985799EA81256784DD8625505EFE271231F57F"
      cert_valid_from     = "2025-01-20"
      cert_valid_to       = "2028-01-20"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5FAR1W6E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "20:22:41:84:d3:de:95:e9:05:51:f9:7f:0c:b9:28:df"
      )
}
