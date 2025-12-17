import "pe"

rule MAL_Compromised_Cert_CobaltStrike_TrustOcean_7A6D30A6EB2FA0C3369283725704AC4C {
   meta:
      description         = "Detects CobaltStrike with compromised cert (TrustOcean)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-28"
      version             = "1.0"

      hash                = "87766b03bd60f023941fc02d8dc5c292136bc5e6e0805cac765929f45e61b90d"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Trade By International ApS"
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "7a:6d:30:a6:eb:2f:a0:c3:36:92:83:72:57:04:ac:4c"
      cert_thumbprint     = "89B2F0B71F97C9ED574409DA7DD47BCAC9083161"
      cert_valid_from     = "2021-04-28"
      cert_valid_to       = "2022-04-28"

      country             = "DK"
      state               = "???"
      locality            = "Odder"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "7a:6d:30:a6:eb:2f:a0:c3:36:92:83:72:57:04:ac:4c"
      )
}
